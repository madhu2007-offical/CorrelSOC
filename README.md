# CorrelSOC

**Multi-agent SIEM pipeline that correlates security events and generates AI-driven incident triage and remediation reports.**

CorrelSOC is an autonomous incident-response pipeline that turns raw, noisy security logs into prioritized, explainable incidents. A deterministic correlation engine groups related events by time and source, then a three-stage agentic reasoning core (Triage → Correlation → Response) maps them to MITRE ATT&CK techniques, assigns severity, and generates a remediation playbook — all visible in a live dashboard.

---

## Problem

SOC teams are overwhelmed by high volumes of raw security events with no built-in correlation, making it difficult to distinguish isolated noise from coordinated multi-stage attacks in real time.

## Solution

CorrelSOC combines a deterministic pre-filtering/correlation engine with a three-agent LLM reasoning pipeline:

- **Triage Agent** — classifies severity and maps events to MITRE ATT&CK techniques
- **Correlation Agent** — detects multi-stage attack chains across related incidents
- **Response Agent** — generates remediation playbooks (immediate actions, investigation steps, long-term fixes)

Results are surfaced through a live Streamlit dashboard that shows the full reasoning trail behind every incident.

---

## Architecture

```
Log Sources (synthetic)
      │
      ▼
Layer 1 — Ingestion & Normalization
      │
      ▼
Layer 2 — Deterministic Correlation Engine (time-window + statistical rules)
      │
      ▼
Layer 3 — Agentic Reasoning Core
   ├── Triage Agent (severity + ATT&CK mapping)
   ├── Correlation Agent (multi-stage attack chain detection)
   └── Response Agent (remediation playbook)
      │
      ▼
Layer 4 — Evaluation (precision / recall / latency)
      │
      ▼
Layer 5 — Dashboard (live incidents + reasoning trail)
```

See [`docs/architecture.md`](docs/architecture.md) for the full diagram.

---

## Project Structure

```
CorrelSOC/
├── data/               # Log generation and sample data
│   ├── log_generator.py
│   └── sample_logs.json
├── correlation/         # Deterministic correlation engine (Layer 2)
│   └── correlator.py
├── agents/              # Agentic reasoning core (Layer 3)
│   ├── triage_agent.py
│   ├── correlation_agent.py
│   ├── response_agent.py
│   └── pipeline.py
├── eval/                # Evaluation harness (Layer 4)
│   ├── labeled_events.json
│   └── evaluate.py
├── dashboard/            # Streamlit dashboard (Layer 5)
│   └── app.py
├── docs/
│   ├── architecture.md
│   └── research_log.md
├── requirements.txt
├── .env.example
└── README.md
```

---

## Setup

1. **Clone the repo**
   ```
   git clone <your-repo-url>
   cd CorrelSOC
   ```

2. **Create a virtual environment and install dependencies**
   ```
   python -m venv venv
   venv\Scripts\activate        # Windows
   pip install -r requirements.txt
   ```

3. **Add your API key**
   ```
   copy .env.example .env
   ```
   Then open `.env` and add your Anthropic API key:
   ```
   ANTHROPIC_API_KEY=sk-ant-your-key-here
   ```
   Get a key from [platform.claude.com](https://platform.claude.com) → API Keys. Never commit `.env` — it's already in `.gitignore`.

4. **Generate sample logs**
   ```
   python data/log_generator.py
   ```

5. **Run the full pipeline**
   ```
   python agents/pipeline.py
   ```

6. **Run evaluation**
   ```
   python eval/evaluate.py
   ```
---

## Deploy to Streamlit Cloud

1. Push the repo to GitHub.
2. Go to https://streamlit.io/cloud and sign in with GitHub.
3. Choose this repository.
4. Set the app file to:
   ```
   streamlit_app.py
   ```
5. Set the Python version to match your project (e.g. 3.13).
6. Add a secret named `ANTHROPIC_API_KEY` in Streamlit Cloud if you want the agents to call Anthropic.

Once deployed, Streamlit Cloud will provide a permanent public URL such as:

- `https://<your-app-name>.streamlit.app`
7. **Launch the dashboard**
   ```
   streamlit run dashboard/app.py
   ```

### Docker deployment

1. Build the container:
   ```bash
   docker build -t correl-soc .
   ```
2. Run it:
   ```bash
   docker run -p 8501:8501 -e ANTHROPIC_API_KEY="sk-ant-your-key-here" correl-soc
   ```

### Docker Compose

1. Create a local `.env` with:
   ```env
   ANTHROPIC_API_KEY=sk-ant-your-key-here
   ```
2. Run:
   ```bash
   docker compose up --build
   ```

### Windows one-click demo

Run:
```powershell
run_demo.bat
```

---

## Performance

*(Fill in after running `eval/evaluate.py`)*

| Metric | Value |
|---|---|
| Precision | — |
| Recall | — |
| F1 Score | — |
| False Positive Rate | — |
| Avg. Latency per Incident | — |

---

## Tech Stack

- **Language:** Python 3.11+
- **Agentic reasoning:** Claude API (Anthropic SDK)
- **Data handling:** pandas, faker
- **Schema validation:** pydantic
- **Evaluation:** scikit-learn
- **Dashboard:** Streamlit, Plotly

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- See [`docs/research_log.md`](docs/research_log.md) for the full research collection log.

---

## Status

🚧 In active development — built for HCIC-SI2026.

## License

MIT
