# Agents

## ThreatFox Daily Report (`threatfox_daily_report.py`)

Pulls ThreatFox IOCs from the last day, creates an AnythingLLM workspace and thread, uploads the raw JSON and a markdown summary, and runs a 4-turn analyst/LLM Q&A (3 mission-tailored questions + 1 “summarize in ≤3 bullets”). Results are visible in AnythingLLM for review.

**Flow:** ThreatFox IOCs → workspace/thread → upload JSON + report → (optional) LLM-generated analyst questions via AnythingLLM `/v1/openai/chat/completions` → 4 stream-chat exchanges → done.

### I/O diagram

Data flow between the orchestrator, local modules, and external services:

```mermaid
flowchart TB
  subgraph input [Input]
    CLI["CLI (--mission)"]
    Env[".env (keys, workspace, USE_LLM_QUESTIONS, etc.)"]
  end

  subgraph orch [threatfox_daily_report.py]
    Main[main]
    BuildMD[build_markdown_report]
    GenQ["generate_questions or _template_questions"]
    Main --> BuildMD
    Main --> GenQ
  end

  subgraph mod [Local module]
    IOC[threatfox_ioc.get_recent_iocs]
  end

  subgraph ext [External services]
    TFA[ThreatFox API]
    ALM[AnythingLLM API]
  end

  CLI --> Main
  Env --> Main
  Main -->|"days"| IOC
  IOC -->|"POST get_iocs"| TFA
  TFA -->|"query_status, count, data"| IOC
  IOC -->|"result"| Main
  Main -->|"normalized"| BuildMD
  BuildMD -->|"markdown"| Main
  Main -->|"workspaces / workspace/new / thread/new"| ALM
  ALM -->|"workspace_slug, thread_slug"| Main
  Main -->|"document/upload (JSON + MD)"| ALM
  Main -->|"mission"| GenQ
  GenQ -->|"3 questions"| Main
  Main -->|"openai/chat/completions if USE_LLM_QUESTIONS"| ALM
  ALM -->|"3 questions"| GenQ
  GenQ --> Main
  Main -->|"stream-chat x4 (message)"| ALM
  ALM -->|"streamed reply"| Main
  Main -->|"stderr: workspace, thread ready"| output [Output]
```

- **Input:** CLI args (`--mission`) and `.env` (ThreatFox key, AnythingLLM key, optional workspace/LLM/USE_LLM_QUESTIONS).
- **threatfox_ioc:** `get_recent_iocs(days)` calls ThreatFox, returns `{query_status, count, data}`.
- **threatfox_daily_report:** Builds markdown from that result; gets/creates workspace and thread; uploads JSON + report; gets 3 questions (AnythingLLM chat/completions or templates); runs 4 stream-chat turns.
- **AnythingLLM:** Workspaces, thread, document upload, `/v1/openai/chat/completions` (question gen), thread stream-chat.
- **Output:** Workspace and thread are ready in AnythingLLM; script logs a one-line summary to stderr.

### Requirements

- `.env` in project root with `THREATFOX_AUTH_KEY` and `ANYTHINGLLM_API_KEY` (see `.env.example`).
- AnythingLLM running (default `http://localhost:3001`).

### Run

From the project root:

```bash
python agents/threatfox_daily_report.py
```

With a mission so questions are focused (e.g. “hunting cobalt strike”, “signs of APT29”):

```bash
python agents/threatfox_daily_report.py --mission "hunting cobalt strike instances"
```

### Env (optional)

| Variable | Purpose |
|----------|---------|
| `ANYTHINGLLM_THREATFOX_WORKSPACE` | Workspace name (default `ThreatFox Daily`). |
| `ANYTHINGLLM_LLM_MODEL` | LLM model override for chat if your instance supports it. |
| `USE_LLM_QUESTIONS` | `1`/`true`/`yes` → generate the 3 analyst questions via AnythingLLM `/v1/openai/chat/completions` (no OpenAI token). |
| `THREATFOX_DAYS` | Days of IOCs (1–7, default 1). |

### Other files

- **`threatfox_ioc.py`** – Fetches recent IOCs from ThreatFox (`get_recent_iocs(days)`). Used by the daily report.
- **`threatfox_reports.py`** – Reserved for report helpers; current logic lives in `threatfox_daily_report.py`.
- **`anythingllm_chat.py`** – Demo chat script (create thread, send a message). Not required by the daily report.
