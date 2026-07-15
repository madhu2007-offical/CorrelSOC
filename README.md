<div align="center"> <img src="assets/<img width="1983" height="793" alt="ChatGPT Image Jul 15, 2026, 04_19_16 PM" src="https://github.com/user-attachments/assets/e7e7c1c0-f39b-41fb-9977-7855c00a4eaf" />
" alt="CorrelSOC banner" width="100%" />
CorrelSOC
Multi-agent SIEM pipeline that correlates security events and generates AI-driven incident triage and remediation reports.

<p> <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" /> <img src="https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" /> <img src="https://img.shields.io/badge/Claude-Sonnet_4.6-D4A574?style=for-the-badge&logo=anthropic&logoColor=white" /> <img src="https://img.shields.io/badge/Pandas-Data-150458?style=for-the-badge&logo=pandas&logoColor=white" /> <img src="https://img.shields.io/badge/Pydantic-Schema-E92063?style=for-the-badge&logo=pydantic&logoColor=white" /> <img src="https://img.shields.io/badge/scikit--learn-Eval-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white" /> <img src="https://img.shields.io/badge/Plotly-Charts-3F4F75?style=for-the-badge&logo=plotly&logoColor=white" /> </p> <p> <img src="https://img.shields.io/badge/status-in%20development-2DD4BF?style=flat-square" /> <img src="https://img.shields.io/badge/license-MIT-4C5A6B?style=flat-square" /> <img src="https://img.shields.io/badge/HCIC--SI2026-project-E5484D?style=flat-square" /> </p> </div>
CorrelSOC is an autonomous incident-response pipeline that turns raw, noisy security logs into prioritized, explainable incidents. A deterministic correlation engine groups related events by time and source, then a three-stage agentic reasoning core (Triage → Correlation → Response) maps them to MITRE ATT&CK techniques, assigns severity, and generates a remediation playbook — all visible in a live dashboard.

Problem
SOC teams are overwhelmed by high volumes of raw security events with no built-in correlation, making it difficult to distinguish isolated noise from coordinated multi-stage attacks in real time.

Solution
CorrelSOC combines a deterministic pre-filtering/correlation engine with a three-agent LLM reasoning pipeline:

Agent	Role
Triage Agent	Classifies severity, maps events to MITRE ATT&CK techniques
Correlation Agent	Detects multi-stage attack chains across related incidents
Response Agent	Generates remediation playbooks (immediate actions, investigation steps, long-term fixes)
Results are surfaced through a live Streamlit dashboard that shows the full reasoning trail behind every incident.

Architecture
<div align="center"> <img src="assets/architecture.png" alt="CorrelSOC architecture diagram" width="85%" /> </div>

Log Sources (synthetic)
      |
      v
Layer 1 -- Ingestion & Normalization
      |
      v
Layer 2 -- Deterministic Correlation Engine (time-window + statistical rules)
      |
      v
Layer 3 -- Agentic Reasoning Core
   |-- Triage Agent (severity + ATT&CK mapping)
   |-- Correlation Agent (multi-stage attack chain detection)
   `-- Response Agent (remediation playbook)
      |
      v
Layer 4 -- Evaluation (precision / recall / latency)
      |
      v
Layer 5 -- Dashboard (live incidents + reasoning trail)
Full diagram source: docs/architecture.md

Project Structure

CorrelSOC/
|-- assets/               # Banner, architecture image, screenshots
|   |-- banner.png
|   `-- architecture.png
|-- data/                  # Log generation and sample data
|   |-- log_generator.py
|   `-- sample_logs.json
|-- correlation/            # Deterministic correlation engine (Layer 2)
|   `-- correlator.py
|-- agents/                 # Agentic reasoning core (Layer 3)
|   |-- triage_agent.py
|   |-- correlation_agent.py
|   |-- response_agent.py
|   `-- pipeline.py
|-- eval/                   # Evaluation harness (Layer 4)
|   |-- labeled_events.json
|   `-- evaluate.py
|-- dashboard/               # Streamlit dashboard (Layer 5)
|   `-- app.py
|-- docs/
|   |-- architecture.md
|   `-- research_log.md
|-- requirements.txt
|-- .env.example
`-- README.md
Setup
1. Clone the repo


bash
git clone <your-repo-url>
cd CorrelSOC
2. Create a virtual environment and install dependencies


bash
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
3. Add your API key


bash
copy .env.example .env
Open .env and add your Anthropic API key:


ANTHROPIC_API_KEY=sk-ant-your-key-here
Get a key from platform.claude.com -> API Keys. Never commit .env -- it's already in .gitignore.

4. Generate sample logs


bash
python data/log_generator.py
5. Run the full pipeline


bash
python agents/pipeline.py
6. Run evaluation


bash
python eval/evaluate.py
7. Launch the dashboard


bash
streamlit run dashboard/app.py
Performance
(Fill in after running eval/evaluate.py)

Metric	Value
Precision	--
Recall	--
F1 Score	--
False Positive Rate	--
Avg. Latency per Incident	--
Tech Stack
<div align="center"> <p> <img src="https://img.shields.io/badge/Language-Python_3.11+-3776AB?style=flat-square&logo=python&logoColor=white" /> <img src="https://img.shields.io/badge/AI_Reasoning-Claude_API-D4A574?style=flat-square&logo=anthropic&logoColor=white" /> <img src="https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B?style=flat-square&logo=streamlit&logoColor=white" /> </p> <p> <img src="https://img.shields.io/badge/Data-Pandas-150458?style=flat-square&logo=pandas&logoColor=white" /> <img src="https://img.shields.io/badge/Synthetic_Data-Faker-6E56CF?style=flat-square" /> <img src="https://img.shields.io/badge/Validation-Pydantic-E92063?style=flat-square&logo=pydantic&logoColor=white" /> </p> <p> <img src="https://img.shields.io/badge/Evaluation-scikit--learn-F7931E?style=flat-square&logo=scikitlearn&logoColor=white" /> <img src="https://img.shields.io/badge/Visualization-Plotly-3F4F75?style=flat-square&logo=plotly&logoColor=white" /> <img src="https://img.shields.io/badge/Framework-MITRE_ATT%26CK-E5484D?style=flat-square" /> </p> </div>
Layer	Technology	Purpose
Language	Python 3.11+	Core implementation
Agentic reasoning	Claude API (Anthropic SDK)	Triage, correlation, and response agents
Data handling	pandas, faker	Log generation, event manipulation
Schema validation	pydantic	Enforces structured JSON between pipeline stages
Evaluation	scikit-learn	Precision, recall, F1, false-positive rate
Dashboard	Streamlit, Plotly	Live incident console and charts
Threat framework	MITRE ATT&CK	Technique mapping for triage
References
MITRE ATT&CK Framework: https://attack.mitre.org/
Full citation log: docs/research_log.md
Status
In active development -- built for HCIC-SI2026.

License
MIT
