# Agents

## ThreatFox Daily Report (`threatfox_daily_report.py`)

Pulls ThreatFox IOCs from the last day, creates an AnythingLLM workspace and thread, uploads the raw JSON and a markdown summary, and runs a 4-turn analyst/LLM Q&A (3 mission-tailored questions + 1 “summarize in ≤3 bullets”). Results are visible in AnythingLLM for review.

**Flow:** ThreatFox IOCs → workspace/thread → upload JSON + report → (optional) LLM-generated analyst questions via AnythingLLM `/v1/openai/chat/completions` → 4 stream-chat exchanges → done.

### I/O diagram

Primary APIs, services, and relationships:

```
  threatfox_daily_report.py
       |                    \
       | get_recent_iocs     \  workspaces, thread/new, document/upload,
       v                      \ openai/chat/completions, stream-chat
  threatfox_ioc  --------->   AnythingLLM API
       |                      (localhost:3001)
       | get_iocs
       v
  ThreatFox API
  (threatfox.abuse.ch)
```

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
