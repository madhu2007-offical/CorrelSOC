# CorrelSOC Architecture

This document describes the layered architecture for CorrelSOC.

## Layers

1. **Layer 1 — Ingestion & Normalization**
   - Synthetic log generator creates sample security events.
   - Events are normalized into a consistent schema for downstream processing.

2. **Layer 2 — Deterministic Correlation Engine**
   - Group events by source IP and user within a time window.
   - Identify candidate incidents using statistical flags such as login failures, port scan patterns, privilege changes, and large data transfers.

3. **Layer 3 — Agentic Reasoning Core**
   - Triage Agent maps candidate incidents to MITRE ATT&CK techniques and assigns severity.
   - Correlation Agent detects multi-stage attack chains across triage results.
   - Response Agent generates a remediation playbook and investigation steps.

4. **Layer 4 — Evaluation**
   - Computes precision, recall, F1 score, false positive rate, and latency estimates.
   - Uses ground truth labels in `eval/labeled_events.json`.

5. **Layer 5 — Dashboard**
   - Streamlit app visualizes the pipeline output, incident summaries, and evaluation metrics.
   - Live demo support via `streamlit run dashboard/app.py`.

## Data flow

```text
sample_logs.json -> correlation engine -> candidate incidents -> triage -> correlation -> response -> incidents_output.json
```