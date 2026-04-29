# 🧠 Nerve — Autonomous Pentest Readiness System

Nerve is an AI-assisted pentest readiness framework focused on defensive workflows: detection, safe validation, risk prioritization, and remediation planning. It uses CrewAI agents to orchestrate reconnaissance, evidence validation, and report generation.

> WARNING: Nerve is intended for defensive use only. It does not produce exploits, payloads, or post-exploitation guidance.

---

**Key features**

- Evidence-first validation (minimize hallucinations)
- Automated recon orchestration (`subfinder`, `httpx`, `nmap`, `nuclei`)
- Safe PoC validation and screenshot capture
- Structured, actionable reports with prioritized findings

---

**What Nerve does NOT do**

- Exploit generation
- Payload crafting
- Post-exploitation assistance

---

**Architecture (high level)**

```text
Target Input -> Planning Agent -> Recon Orchestrator -> Recon Agents
                           -> Web Crawler -> Vulnerability Scanner
                           -> PoC Validator -> Severity Analyst -> Report Agent

Output: report.md, screenshots/, logs/
```

---

**Requirements**

- Python >= 3.10, < 3.14
- pip
- UV (recommended): https://docs.astral.sh/uv/
- CrewAI (agent orchestration)

---

**Installation & Quickstart**

Clone the repository and install minimal dependencies:

```bash
git clone https://github.com/Theodorio/nerve.git
cd nerve
pip install -r requirements.txt   # if provided; otherwise install uv and development deps
pip install uv
uv sync                           # sync UV-managed environment (if used)
```

Environment variables

Copy `.env.example` to `.env` and set required keys:

```env
OPENAI_API_KEY=your_openai_key_here
WHATSAPP_ALLOWED_SENDERS=+1234567890,+0987654321
```

---

**Running**

Start the full pipeline (CrewAI orchestrator):

```bash
crewai run
```

Run the optional WhatsApp command bot (example):

```bash
# local dev (uses UV to run uvicorn)
uv run uvicorn src.nerve.whatsapp_bot:app --host 0.0.0.0 --port 8000 --reload
```

**WhatsApp bot — supported commands**

| Command | Description |
|---|---|
| help | Show available commands |
| status | Show current scan status |
| run | Start scan pipeline |
| report | Return summary report |

Restrict access to allowed senders via `WHATSAPP_ALLOWED_SENDERS`.

---

**Output layout**

```
output/
├── report.md
├── screenshots/
└── logs/
```

---

**Known limitations**

- Some tool integrations may be environment-dependent.
- Error handling and tool fallbacks are actively improved.

---

Contributing

- This repository is under active development. If you'd like to contribute, open an issue or a pull request.

