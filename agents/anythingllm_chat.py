#!/usr/bin/env python3
"""
Create a new AnythingLLM chat and ask a math question.

Uses ANYTHINGLLM_API_KEY from .env. AnythingLLM should be running locally
(default http://localhost:3001). API docs: http://localhost:3001/api/docs/

On AnythingLLM Desktop the API key is the default (only) user's key, so workspaces
and chats created with it appear under that user. If no workspace exists, the script
creates one. Chat is sent via the stream-chat endpoint so the conversation is
persisted. Each run creates a new thread named with the current time
(e.g. 2026-01-28 00:45:30) so it appears as its own conversation in the UI.
"""

import json
import os
import sys
import uuid
from datetime import datetime

import requests
from dotenv import load_dotenv

# Load .env from project root (parent of agents/)
_load_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(_load_dir, ".env"))

DEFAULT_BASE_URL = "http://localhost:3001"
DEFAULT_WORKSPACE_NAME = "Script Chat"
MATH_QUESTION = "What is 17 * 23? Please state only the number."


def _headers(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def get_workspaces(base_url: str, api_key: str) -> list[dict]:
    """Return the list of workspaces for the authenticated user."""
    url = f"{base_url.rstrip('/')}/api/v1/workspaces"
    resp = requests.get(url, headers=_headers(api_key), timeout=30)
    resp.raise_for_status()
    return resp.json().get("workspaces") or []


def get_workspace_slug(
    base_url: str, api_key: str, preferred_name: str | None = None
) -> str | None:
    """
    Return the slug of a workspace. If preferred_name is set, use the workspace
    whose name equals it (case-insensitive); otherwise use the first workspace.
    """
    workspaces = get_workspaces(base_url, api_key)
    if not workspaces:
        return None
    if preferred_name:
        key = preferred_name.strip().lower()
        for ws in workspaces:
            n = (ws.get("name") or "").strip().lower()
            if n == key:
                return ws.get("slug")
        return None
    return workspaces[0].get("slug")


def create_workspace(
    base_url: str, api_key: str, name: str = DEFAULT_WORKSPACE_NAME
) -> str | None:
    """
    Create a workspace and return its slug.

    Uses POST /api/v1/workspaces. Request/response shape may vary by AnythingLLM
    version; see http://localhost:3001/api/docs/ for your instance.
    """
    url = f"{base_url.rstrip('/')}/api/v1/workspaces"
    body = {"name": name}
    resp = requests.post(
        url, headers={**_headers(api_key), "Content-Type": "application/json"}, json=body, timeout=30
    )
    resp.raise_for_status()
    data = resp.json()
    # Accept slug from top level or from workspace object
    slug = data.get("slug") or (data.get("workspace") or {}).get("slug")
    if slug:
        return slug
    # If response is workspace list or similar, take first
    workspaces = data.get("workspaces") or []
    if workspaces:
        w = workspaces[0]
        return w.get("slug") if isinstance(w, dict) else w
    return None


def _thread_slug_and_name() -> tuple[str, str]:
    """Return (thread_slug, thread_display_name) from current time."""
    now = datetime.now()
    slug = now.strftime("%Y-%m-%d-%H-%M-%S")
    name = now.strftime("%Y-%m-%d %H:%M:%S")
    return slug, name


def create_thread(
    base_url: str,
    api_key: str,
    workspace_slug: str,
    name: str,
    slug: str,
) -> str | None:
    """
    Create a new thread in the workspace via POST /api/v1/workspace/{slug}/thread/new.

    Request body: name (display name), slug (thread slug). Optional: userId.
    Response: { "thread": { "slug": "...", ... } }.
    """
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
    except requests.RequestException:
        return None
    try:
        data = resp.json()
    except Exception:
        return None
    thread = data.get("thread") or {}
    return thread.get("slug")


def _new_thread_slug() -> str:
    """Return a new UUID-based slug for use as thread_slug (create-on-first-use)."""
    return str(uuid.uuid4())


def chat_stream(
    base_url: str,
    api_key: str,
    workspace_slug: str,
    message: str,
    *,
    thread_slug: str | None = None,
    thread_name: str | None = None,
) -> tuple[str, dict | None]:
    """
    Send a message via stream-chat so the conversation is persisted.

    If thread_slug is set, uses POST .../workspace/{slug}/thread/{thread_slug}/stream-chat
    so the message goes to that thread (creating it if needed). Otherwise uses
    workspace-level stream-chat. thread_name can be sent in the body when
    creating a new thread if the API supports it.
    """
    if thread_slug:
        url = f"{base_url.rstrip('/')}/api/v1/workspace/{workspace_slug}/thread/{thread_slug}/stream-chat"
    else:
        url = f"{base_url.rstrip('/')}/api/v1/workspace/{workspace_slug}/stream-chat"
    headers = {**_headers(api_key), "Content-Type": "application/json"}
    body: dict = {"message": message, "mode": "chat"}
    if thread_name is not None:
        body["threadName"] = thread_name
    resp = requests.post(
        url, headers=headers, json=body, timeout=120, stream=True
    )
    resp.raise_for_status()

    chunks: list[str] = []
    last_event: dict | None = None

    for line in resp.iter_lines(decode_unicode=True):
        if not line:
            continue
        raw = line.strip()
        if raw.startswith("data: "):
            raw = raw[6:]
        if raw == "[DONE]" or raw == "":
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        last_event = event
        # Accumulate text from streamed textResponse events
        part = event.get("textResponse") or event.get("text") or event.get("delta") or ""
        if isinstance(part, str) and part:
            chunks.append(part)

    return "".join(chunks), last_event


def main() -> None:
    api_key = os.getenv("ANYTHINGLLM_API_KEY")
    if not api_key or api_key == "your-api-key-here":
        print(
            "ANYTHINGLLM_API_KEY not set or still placeholder. Set it in .env (see .env.example).",
            file=sys.stderr,
        )
        sys.exit(1)

    base_url = os.getenv("ANYTHINGLLM_BASE_URL", DEFAULT_BASE_URL)
    preferred_workspace = os.getenv("ANYTHINGLLM_WORKSPACE_NAME", "").strip() or None

    try:
        slug = get_workspace_slug(base_url, api_key, preferred_name=preferred_workspace)
    except requests.RequestException as e:
        print(f"Failed to list workspaces: {e}", file=sys.stderr)
        if hasattr(e, "response") and e.response is not None:
            print(f"Response: {e.response.text[:500]}", file=sys.stderr)
        sys.exit(1)

    if not slug:
        if preferred_workspace:
            print(
                f"Workspace \"{preferred_workspace}\" not found. Set ANYTHINGLLM_WORKSPACE_NAME to a workspace name or leave unset to use the first workspace.",
                file=sys.stderr,
            )
            sys.exit(1)
        workspace_name = DEFAULT_WORKSPACE_NAME
        try:
            slug = create_workspace(base_url, api_key, name=workspace_name)
        except requests.RequestException as e:
            print(f"Failed to create workspace: {e}", file=sys.stderr)
            if hasattr(e, "response") and e.response is not None:
                print(f"Response: {e.response.text[:500]}", file=sys.stderr)
            sys.exit(1)
        if not slug:
            print(
                "Created workspace but could not get slug. Check API response shape at /api/docs/.",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"Created workspace \"{workspace_name}\" (slug: {slug}).", file=sys.stderr)

    thread_slug_req, thread_name = _thread_slug_and_name()
    created_slug = create_thread(
        base_url, api_key, slug, name=thread_name, slug=thread_slug_req
    )
    if created_slug:
        thread_slug: str | None = created_slug
        print(f"New thread: {thread_name} (slug: {thread_slug})", file=sys.stderr)
    else:
        thread_slug = _new_thread_slug()
        print(f"New thread: {thread_name} (slug: {thread_slug})", file=sys.stderr)

    try:
        text, last_event = chat_stream(
            base_url, api_key, slug, MATH_QUESTION,
            thread_slug=thread_slug, thread_name=thread_name,
        )
    except requests.RequestException as e:
        if not created_slug and thread_slug and hasattr(e, "response") and e.response is not None:
            status = getattr(e.response, "status_code", None)
            if status in (400, 404):
                print(
                    f"Thread endpoint not available ({status}), using workspace-level chat.",
                    file=sys.stderr,
                )
                thread_slug = None
                text, last_event = chat_stream(
                    base_url, api_key, slug, MATH_QUESTION,
                    thread_slug=None, thread_name=thread_name,
                )
            else:
                print(f"Chat request failed: {e}", file=sys.stderr)
                print(f"Response: {e.response.text[:500]}", file=sys.stderr)
                sys.exit(1)
        else:
            print(f"Chat request failed: {e}", file=sys.stderr)
            if hasattr(e, "response") and e.response is not None:
                print(f"Response: {e.response.text[:500]}", file=sys.stderr)
            sys.exit(1)

    # Use streamed text, or fall back to textResponse/response from last event
    if not text and last_event:
        text = (
            last_event.get("textResponse")
            or last_event.get("response")
            or last_event.get("text")
            or last_event.get("answer")
            or last_event.get("message")
            or last_event.get("content")
            or ""
        )
        if not isinstance(text, str):
            text = str(text) if text is not None else ""
    if text:
        print(f"Question: {MATH_QUESTION}")
        print(f"Answer: {text}")
    elif last_event:
        print(last_event)
    else:
        print("No response text received.")


if __name__ == "__main__":
    main()
