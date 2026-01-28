#!/usr/bin/env python3
"""
ThreatFox daily report tool: pull IOCs from the last day, create an AnythingLLM
workspace/thread, upload JSON + markdown report, and run a simulated 3-message
analyst/LLM conversation so a human can review in AnythingLLM.

Uses agents/threatfox_ioc.get_recent_iocs and AnythingLLM APIs (workspace, thread,
document upload, stream-chat). Env: THREATFOX_AUTH_KEY, ANYTHINGLLM_API_KEY;
optional ANYTHINGLLM_BASE_URL, ANYTHINGLLM_THREATFOX_WORKSPACE, USE_LLM_QUESTIONS,
OPENAI_API_KEY. See .env.example.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv

# Project root = parent of agents/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

# Ensure agents dir is on path so threatfox_ioc is importable when run as script
_agents_dir = Path(__file__).resolve().parent
if str(_agents_dir) not in sys.path:
    sys.path.insert(0, str(_agents_dir))
from threatfox_ioc import get_recent_iocs  # noqa: E402

DEFAULT_BASE_URL = "http://localhost:3001"
DEFAULT_THREATFOX_WORKSPACE = "ThreatFox Daily"
TEMPLATE_QUESTIONS = [
    "What are the most critical IOCs in this dataset and why?",
    "Which malware families appear most often and what should we prioritize for blocking?",
    "Summarize key recommendations for our SOC based on this ThreatFox pull.",
]
QUESTION_GEN_PROMPT = (
    "Using only the ThreatFox IOC data in this workspace, output exactly 3 concise "
    "questions an expert security analyst would ask, one per line, numbered 1–3."
)
SAMPLE_IOC_ROWS = 15
EMBED_WAIT_SECONDS = 5


def _headers(api_key: str) -> dict:
    """Auth headers for AnythingLLM: Bearer (per OpenAPI) and X-API-Key (some instances)."""
    return {
        "Authorization": f"Bearer {api_key}",
        "X-API-Key": api_key,
    }


def get_workspaces(base_url: str, api_key: str) -> list[dict]:
    """Return the list of workspaces for the authenticated user."""
    url = f"{base_url.rstrip('/')}/api/v1/workspaces"
    resp = requests.get(url, headers=_headers(api_key), timeout=30)
    resp.raise_for_status()
    return resp.json().get("workspaces") or []


def get_workspace_slug(
    base_url: str, api_key: str, preferred_name: str | None = None
) -> str | None:
    """Return the slug of a workspace by name (case-insensitive), or None."""
    workspaces = get_workspaces(base_url, api_key)
    if not workspaces:
        return None
    if not preferred_name:
        return workspaces[0].get("slug")
    key = preferred_name.strip().lower()
    for ws in workspaces:
        n = (ws.get("name") or "").strip().lower()
        if n == key:
            return ws.get("slug")
    return None


def create_workspace(base_url: str, api_key: str, name: str) -> str | None:
    """Create a workspace and return its slug. Uses POST /api/v1/workspace/new (per OpenAPI)."""
    url = f"{base_url.rstrip('/')}/api/v1/workspace/new"
    body = {"name": name}
    resp = requests.post(
        url,
        headers={**_headers(api_key), "Content-Type": "application/json"},
        json=body,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    slug = data.get("slug") or (data.get("workspace") or {}).get("slug")
    if slug:
        return slug
    workspaces = data.get("workspaces") or []
    if workspaces:
        w = workspaces[0]
        return w.get("slug") if isinstance(w, dict) else w
    return None


def create_thread(
    base_url: str,
    api_key: str,
    workspace_slug: str,
    name: str,
    slug: str,
) -> str | None:
    """Create a new thread in the workspace; returns thread slug or None."""
    url = f"{base_url.rstrip('/')}/api/v1/workspace/{workspace_slug}/thread/new"
    body = {"name": name, "slug": slug}
    try:
        resp = requests.post(
            url,
            headers={**_headers(api_key), "Content-Type": "application/json"},
            json=body,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        thread = data.get("thread") or {}
        return thread.get("slug")
    except requests.RequestException:
        return None


def chat_stream(
    base_url: str,
    api_key: str,
    workspace_slug: str,
    message: str,
    *,
    thread_slug: str,
) -> str:
    """Send a message to the thread via stream-chat and return full assistant text."""
    url = f"{base_url.rstrip('/')}/api/v1/workspace/{workspace_slug}/thread/{thread_slug}/stream-chat"
    headers = {**_headers(api_key), "Content-Type": "application/json"}
    body = {"message": message, "mode": "chat"}
    resp = requests.post(url, headers=headers, json=body, timeout=120, stream=True)
    resp.raise_for_status()

    chunks: list[str] = []
    for line in resp.iter_lines(decode_unicode=True):
        if not line:
            continue
        raw = line.strip()
        if raw.startswith("data: "):
            raw = raw[6:]
        if raw in ("[DONE]", ""):
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        part = event.get("textResponse") or event.get("text") or event.get("delta") or ""
        if isinstance(part, str) and part:
            chunks.append(part)
    return "".join(chunks)


def build_markdown_report(result: dict, days: int = 1) -> str:
    """Build a markdown report from ThreatFox API result (query_status, count, data)."""
    status = result.get("query_status", "unknown")
    count = result.get("count", 0) or len(result.get("data") or [])
    data = result.get("data") or []
    now = datetime.utcnow()
    date_range = f"last {days} day(s)" if days != 1 else "last 1 day"

    lines = [
        f"# ThreatFox IOCs – {date_range}",
        "",
        f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        "",
        "## Summary",
        "",
        f"- **Query status:** {status}",
        f"- **Total indicators:** {count}",
        "",
    ]

    if data:
        malware_counter: Counter[str] = Counter()
        threat_counter: Counter[str] = Counter()
        for row in data:
            mp = row.get("malware_printable") or row.get("malware") or "Unknown"
            malware_counter[mp] += 1
            tt = row.get("threat_type") or row.get("threat_type_desc") or "Unknown"
            threat_counter[tt] += 1

        lines.extend(["### Top malware families", ""])
        for name, n in malware_counter.most_common(10):
            lines.append(f"- {name}: {n}")
        lines.append("")

        lines.extend(["### Top threat types", ""])
        for name, n in threat_counter.most_common(10):
            lines.append(f"- {name}: {n}")
        lines.append("")

    lines.extend(["## Sample IOCs", ""])
    lines.append("| IOC | Malware | Threat type | First seen | Confidence |")
    lines.append("|-----|---------|-------------|------------|------------|")
    for row in data[:SAMPLE_IOC_ROWS]:
        ioc = (row.get("ioc") or "").replace("|", "\\|")
        mal = (row.get("malware_printable") or row.get("malware") or "").replace("|", "\\|")
        tt = (row.get("threat_type") or "").replace("|", "\\|")
        first = (row.get("first_seen") or "").replace("|", "\\|")
        conf = row.get("confidence_level", "")
        lines.append(f"| {ioc} | {mal} | {tt} | {first} | {conf} |")
    lines.append("")
    lines.append("The full dataset is available in the attached JSON document in this workspace.")
    return "\n".join(lines)


def upload_document(
    base_url: str,
    api_key: str,
    file_path: Path,
    workspace_slug: str,
    *,
    title: str | None = None,
    doc_source: str | None = None,
) -> dict:
    """Upload a file to AnythingLLM and add it to the given workspace."""
    url = f"{base_url.rstrip('/')}/api/v1/document/upload"
    headers = _headers(api_key)
    # Infer content type from suffix
    suffix = file_path.suffix.lower()
    content_type = "application/json" if suffix == ".json" else "text/markdown"
    with open(file_path, "rb") as f:
        files = {"file": (file_path.name, f, content_type)}
        data: dict = {"addToWorkspaces": workspace_slug}
        if title or doc_source:
            meta: dict = {}
            if title:
                meta["title"] = title
            if doc_source:
                meta["docSource"] = doc_source
            data["metadata"] = json.dumps(meta) if isinstance(meta, dict) else meta
        resp = requests.post(url, headers=headers, files=files, data=data, timeout=120)
    resp.raise_for_status()
    return resp.json()


def generate_questions_via_anythingllm(
    base_url: str,
    api_key: str,
    workspace_slug: str,
    thread_slug: str,
) -> list[str] | None:
    """Ask AnythingLLM for 3 analyst questions; returns parsed list or None."""
    try:
        text = chat_stream(
            base_url, api_key, workspace_slug, QUESTION_GEN_PROMPT, thread_slug=thread_slug
        )
    except requests.RequestException:
        return None
    if not text or not text.strip():
        return None
    # Parse "1. ..." or "1) ..." or first three non-empty lines
    questions: list[str] = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        # Remove leading "1.", "1)", "1 -", etc.
        m = re.match(r"^\d+[.)\-\s]+\s*(.+)$", line, re.IGNORECASE)
        if m:
            questions.append(m.group(1).strip())
        else:
            questions.append(line)
        if len(questions) >= 3:
            return questions[:3]
    return questions[:3] if len(questions) >= 3 else None


def generate_questions_via_openai(result: dict) -> list[str] | None:
    """Use OpenAI (or compatible) API to generate 3 analyst questions; returns list or None."""
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None
    count = result.get("count", 0) or len(result.get("data") or [])
    data = result.get("data") or []
    malware_counts: dict[str, int] = {}
    for row in data[:100]:
        mp = row.get("malware_printable") or row.get("malware") or "Unknown"
        malware_counts[mp] = malware_counts.get(mp, 0) + 1
    top = sorted(malware_counts.items(), key=lambda x: -x[1])[:5]
    summary = f"ThreatFox pull: {count} IOCs. Top malware: " + ", ".join(
        f"{n}({c})" for n, c in top
    )
    prompt = (
        f"Context: {summary}. Output exactly 3 concise questions an expert security "
        "analyst would ask about this data, one per line, numbered 1–3."
    )
    base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    url = f"{base}/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    body = {
        "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 300,
    }
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        data_resp = resp.json()
        content = (data_resp.get("choices") or [{}])[0].get("message", {}).get("content") or ""
    except requests.RequestException:
        return None
    if not content.strip():
        return None
    questions = []
    for line in content.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^\d+[.)\-\s]+\s*(.+)$", line, re.IGNORECASE)
        if m:
            questions.append(m.group(1).strip())
        else:
            questions.append(line)
        if len(questions) >= 3:
            return questions[:3]
    return questions[:3] if len(questions) >= 3 else None


def main() -> None:
    # 1. Env and validation
    project_root = PROJECT_ROOT
    if not project_root.joinpath(".env").exists():
        pass  # dotenv will no-op; required vars checked below
    auth_key = os.getenv("THREATFOX_AUTH_KEY", "").strip()
    if not auth_key or auth_key == "your-auth-key-here":
        print("THREATFOX_AUTH_KEY not set or placeholder. Set it in .env.", file=sys.stderr)
        sys.exit(1)
    api_key = os.getenv("ANYTHINGLLM_API_KEY", "").strip()
    if not api_key or api_key == "your-api-key-here":
        print("ANYTHINGLLM_API_KEY not set or placeholder. Set it in .env.", file=sys.stderr)
        sys.exit(1)
    base_url = os.getenv("ANYTHINGLLM_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    workspace_name = (
        os.getenv("ANYTHINGLLM_THREATFOX_WORKSPACE", "").strip()
        or DEFAULT_THREATFOX_WORKSPACE
    )
    use_llm_questions = os.getenv("USE_LLM_QUESTIONS", "").strip().lower() in ("1", "true", "yes")

    # 2. ThreatFox IOCs (last 1 day)
    days = int(os.getenv("THREATFOX_DAYS", "1"))
    try:
        result = get_recent_iocs(days=days)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as e:
        print(f"ThreatFox request failed: {e}", file=sys.stderr)
        sys.exit(1)
    status = result.get("query_status", "unknown")
    if status != "ok":
        print(f"ThreatFox query_status: {status}", file=sys.stderr)
        if result.get("data"):
            print(result["data"], file=sys.stderr)
        sys.exit(1)
    data = result.get("data") or []
    count = len(data)
    normalized = {"query_status": status, "count": count, "data": data}

    # 3. Workspace and thread
    try:
        ws_slug = get_workspace_slug(base_url, api_key, preferred_name=workspace_name)
    except requests.RequestException as e:
        print(f"Failed to list workspaces: {e}", file=sys.stderr)
        sys.exit(1)
    if not ws_slug:
        try:
            ws_slug = create_workspace(base_url, api_key, workspace_name)
        except requests.RequestException as e:
            print(f"Failed to create workspace: {e}", file=sys.stderr)
            sys.exit(1)
        if not ws_slug:
            print("Could not create or resolve workspace slug.", file=sys.stderr)
            sys.exit(1)
        print(f"Created workspace \"{workspace_name}\" (slug: {ws_slug})", file=sys.stderr)

    thread_name = f"ThreatFox IOCs {datetime.now().strftime('%Y-%m-%d')} ({count} indicators)"
    thread_slug = datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + "-" + str(uuid.uuid4())[:8]
    created_slug = create_thread(base_url, api_key, ws_slug, name=thread_name, slug=thread_slug)
    if created_slug:
        thread_slug = created_slug
    print(f"Thread: {thread_name} (slug: {thread_slug})", file=sys.stderr)

    # 4. Markdown report + temp files, upload both
    md_content = build_markdown_report(normalized, days=days)
    with tempfile.TemporaryDirectory(prefix="threatfox_report_") as tmpdir:
        tdir = Path(tmpdir)
        json_path = tdir / "threatfox_iocs.json"
        md_path = tdir / "threatfox_report.md"
        json_path.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
        md_path.write_text(md_content, encoding="utf-8")

        try:
            upload_document(
                base_url,
                api_key,
                json_path,
                ws_slug,
                title="ThreatFox IOCs (full JSON)",
                doc_source="ThreatFox API daily pull",
            )
            upload_document(
                base_url,
                api_key,
                md_path,
                ws_slug,
                title="ThreatFox report (markdown)",
                doc_source="Generated summary from ThreatFox IOCs",
            )
        except requests.RequestException as e:
            print(f"Document upload failed: {e}", file=sys.stderr)
            sys.exit(1)

    # 5. Optional wait for embeddings
    if EMBED_WAIT_SECONDS > 0:
        time.sleep(EMBED_WAIT_SECONDS)

    # 6. Analyst questions
    questions: list[str] = []
    if use_llm_questions:
        q = generate_questions_via_anythingllm(base_url, api_key, ws_slug, thread_slug)
        if q and len(q) == 3:
            questions = q
        if not questions:
            q = generate_questions_via_openai(normalized)
            if q and len(q) == 3:
                questions = q
    if not questions:
        questions = list(TEMPLATE_QUESTIONS)

    # 7. Three stream-chat exchanges
    for i, q in enumerate(questions, 1):
        try:
            reply = chat_stream(base_url, api_key, ws_slug, q, thread_slug=thread_slug)
            print(f"[{i}/3] Q: {q[:60]}... -> {len(reply)} chars", file=sys.stderr)
        except requests.RequestException as e:
            print(f"Chat {i} failed: {e}", file=sys.stderr)

    # 8. Summary
    print(f"Workspace \"{workspace_name}\" (slug: {ws_slug}), thread \"{thread_name}\" ready.", file=sys.stderr)


if __name__ == "__main__":
    main()
