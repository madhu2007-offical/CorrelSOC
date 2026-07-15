# CorrelSOC

CorrelSOC is an autonomous incident-response pipeline that turns raw, noisy security logs into prioritized, explainable incidents. A deterministic correlation engine groups related events by time and source, then a three-stage agentic reasoning core (Triage -> Correlation -> Response) maps them to MITRE ATT&CK techniques, assigns severity, and generates a remediation playbook, all visible in a live dashboard.

## Project Setup

1. Create a Python virtual environment
   ```bash
   python -m venv venv
   source venv/bin/activate  # macOS/Linux
   venv\Scripts\activate   # Windows
   ```
2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
3. Copy `.env.example` to `.env` and add your Anthropic API key
   ```bash
   cp .env.example .env
   ```
4. Run the pipeline and dashboard as needed.

## Architecture

- Log ingestion generates synthetic security logs
- Deterministic correlation engine groups and flags candidate incidents
- Agentic reasoning core enriches incidents with MITRE mapping, correlation, and response guidance
- Evaluation computes precision, recall, F1, and false positives
- Dashboard visualizes live logs, incidents, and reasoning

> Architecture diagram placeholder (Mermaid diagram will be added later)
