import json
import subprocess
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
EVAL_DIR = ROOT / "eval"
PIPELINE_PATH = ROOT / "agents" / "pipeline.py"


def load_json(path: Path):
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run_pipeline() -> str:
    process = subprocess.run(
        [sys.executable, str(PIPELINE_PATH)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    output = process.stdout + "\n" + process.stderr
    return output.strip()


def build_table(data, prefix=""):
    if data is None:
        return None
    df = pd.json_normalize(data)
    return df


st.set_page_config(page_title="CorrelSOC Live Demo", layout="wide")
st.title("CorrelSOC Live Demo")
st.markdown(
    "This dashboard presents the incident pipeline output, evaluation metrics, and sample logs for the CorrelSOC project."
)

if st.button("Run pipeline now"):
    with st.spinner("Running the CorrelSOC pipeline..."):
        output = run_pipeline()
    st.code(output, language="bash")

sample_logs = load_json(DATA_DIR / "sample_logs.json")
incidents_output = load_json(DATA_DIR / "incidents_output.json")
eval_results = load_json(EVAL_DIR / "results.json")

if incidents_output is None:
    st.warning("No pipeline output found. Run the pipeline or generate incidents first.")
    st.stop()

candidate_incidents = incidents_output.get("candidate_incidents", [])
triage_results = incidents_output.get("triage_results", [])
response_results = incidents_output.get("response_results", [])
correlation_result = incidents_output.get("correlation_result", {})
metadata = incidents_output.get("metadata", {})

with st.expander("Pipeline metadata"):
    st.json(metadata)

col1, col2 = st.columns(2)
with col1:
    st.subheader("Evaluation Summary")
    if eval_results is not None:
        metrics = eval_results.get("metrics", {})
        summary = metrics.get("summary", {})
        st.metric("Weighted Precision", f"{summary.get('precision_weighted',0):.2f}")
        st.metric("Weighted Recall", f"{summary.get('recall_weighted',0):.2f}")
        st.metric("Weighted F1", f"{summary.get('f1_weighted',0):.2f}")
        st.metric("False Positive Rate", f"{metrics.get('false_positive_rate',0.0):.2%}")
    else:
        st.info("Evaluation results not available yet.")

with col2:
    st.subheader("Pipeline Summary")
    st.metric("Candidate incidents", len(candidate_incidents))
    st.metric("Triage results", len(triage_results))
    st.metric("Response results", len(response_results))

with st.expander("Correlation result"):
    st.json(correlation_result)

if candidate_incidents:
    st.markdown("## Candidate incidents")
    df_candidates = build_table(candidate_incidents)
    if df_candidates is not None:
        if "flags" in df_candidates.columns:
            df_candidates["flags"] = df_candidates["flags"].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)
        st.dataframe(df_candidates)

if triage_results:
    st.markdown("## Triage results")
    df_triage = build_table(triage_results)
    if df_triage is not None:
        st.dataframe(df_triage)

if response_results:
    st.markdown("## Response results")
    df_response = build_table(response_results)
    if df_response is not None:
        st.dataframe(df_response)

if sample_logs:
    st.markdown("## Sample logs")
    df_logs = build_table(sample_logs)
    if df_logs is not None:
        st.dataframe(df_logs.head(50))

if triage_results:
    df_triage = build_table(triage_results)
    if df_triage is not None and "severity" in df_triage.columns:
        st.markdown("## Severity distribution")
        fig = px.histogram(df_triage, x="severity", title="Triage severity distribution")
        st.plotly_chart(fig, use_container_width=True)

if triage_results:
    df_triage = build_table(triage_results)
    if df_triage is not None and "mitre_attack_id" in df_triage.columns:
        st.markdown("## MITRE attack counts")
        fig = px.bar(df_triage["mitre_attack_id"].value_counts().reset_index(), x="index", y="mitre_attack_id", labels={"index":"MITRE Attack ID","mitre_attack_id":"Count"})
        st.plotly_chart(fig, use_container_width=True)

st.markdown("---")
st.write(
    "### Run instructions\n1. Ensure dependencies are installed with `pip install -r requirements.txt`.\n2. Set `ANTHROPIC_API_KEY` in `.env`.\n3. Run `streamlit run dashboard/app.py`."
)
