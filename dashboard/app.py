import json
import os
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
EVAL_DIR = ROOT / "eval"
PIPELINE_PATH = ROOT / "agents" / "pipeline.py"

SEVERITY_PALETTE = {
    "Critical": "#E5484D",
    "High": "#F5A524",
    "Medium": "#F5D90A",
    "Low": "#3B82F6",
    "Benign": "#4C5A6B",
    "Info": "#4C5A6B",
}

EVENT_ICON_MAP = {
    "possible_brute_force": "shield-alert",
    "possible_port_scan": "radar",
    "possible_exfiltration": "upload-cloud",
    "possible_privilege_escalation": "key",
    "suspicious_cluster": "circle-check",
}


def load_json(path: Path):
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_table(data):
    if data is None:
        return None
    return pd.json_normalize(data)


def get_severity_badge(severity: str) -> str:
    color = SEVERITY_PALETTE.get(severity, "#4C5A6B")
    return f'<span class="badge badge-{severity.lower()}">\n  <span class="badge-dot" style="background:{color}"></span>\n  <span>{severity}</span>\n</span>'


def svg_icon(name: str, color: str = "#2DD4BF") -> str:
    icons = {
        "shield-alert": '<svg viewBox="0 0 24 24" fill="none"><path d="M12 3L5 6v5c0 5 3.3 8 7 9 3.7-1 7-4 7-9V6l-7-3z" stroke="currentColor" stroke-width="1.8"/><path d="M12 8v4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="17" r="1" fill="currentColor"/></svg>',
        "radar": '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="8" stroke="currentColor" stroke-width="1.8"/><path d="M12 4a8 8 0 0 1 5 13" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M12 12l5 2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
        "upload-cloud": '<svg viewBox="0 0 24 24" fill="none"><path d="M16 16v5H8v-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M12 16V8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M9 11l3-3 3 3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
        "download-cloud": '<svg viewBox="0 0 24 24" fill="none"><path d="M8 8a4 4 0 0 1 8 0" stroke="currentColor" stroke-width="1.8"/><path d="M12 20v-6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="m9 15 3 3 3-3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
        "key": '<svg viewBox="0 0 24 24" fill="none"><circle cx="7" cy="17" r="3" stroke="currentColor" stroke-width="1.8"/><path d="M10 17h8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M18 17v-2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M18 15v-2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
        "circle-check": '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="8" stroke="currentColor" stroke-width="1.8"/><path d="m9.5 12.5 1.7 1.7 3.8-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
        "search": '<svg viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="6" stroke="currentColor" stroke-width="1.8"/><path d="m17 17 4 4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    }
    svg = icons.get(name, icons["search"])
    return f'<span class="icon" style="color:{color}">{svg}</span>'


def render_header():
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
        html, body, [class*="css"]  {
            background: #0B0E11 !important;
            color: #E2E8F0;
            font-family: 'Inter', sans-serif;
        }
        .block-container {
            padding: 24px 28px 28px !important;
        }
        .stApp {
            background: #0B0E11;
        }
        .title {
            font-size: 2.4rem;
            font-weight: 700;
        }
        .section-subtitle {
            color: #94A3B8;
            margin-top: -6px;
            margin-bottom: 18px;
            font-size: 0.95rem;
        }
        .soc-card {
            background: #151920;
            border: 1px solid #252B33;
            border-radius: 4px;
            padding: 22px;
            margin-bottom: 18px;
        }
        .soc-card h3 {
            margin: 0 0 10px;
            color: #F8FAFC;
            font-size: 1rem;
            font-weight: 600;
        }
        .soc-card .content-row {
            display: flex;
            gap: 14px;
            flex-wrap: wrap;
        }
        .metric-card {
            flex: 1 1 180px;
            min-width: 180px;
            background: #11161D;
            border: 1px solid #252B33;
            padding: 18px;
            border-radius: 4px;
        }
        .metric-card small {
            color: #94A3B8;
        }
        .metric-card .value {
            font-size: 1.9rem;
            font-weight: 700;
            color: #F8FAFC;
            font-family: 'JetBrains Mono', monospace;
        }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-size: 0.88rem;
            color: #E2E8F0;
            border: 1px solid rgba(226,232,240,0.12);
            padding: 6px 10px;
            border-radius: 999px;
            background: rgba(226,232,240,0.03);
        }
        .badge-dot {
            width: 10px;
            height: 10px;
            border-radius: 999px;
            display: inline-block;
        }
        .icon {
            display: inline-flex;
            width: 18px;
            height: 18px;
            margin-right: 6px;
        }
        .icon svg {
            width: 18px;
            height: 18px;
            stroke: currentColor;
        }
        .grid-two {
            display: grid;
            grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr);
            gap: 20px;
        }
        .flat-table thead tr th {
            color: #94A3B8;
            border-bottom: 1px solid #252B33;
            padding-bottom: 10px;
        }
        .flat-table tbody tr td {
            border-bottom: 1px solid #252B33;
            padding: 10px 0;
            color: #CBD5E1;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.95rem;
        }
        .flat-table tbody tr:last-child td {
            border-bottom: none;
        }
        .table-section {
            overflow-x: auto;
            padding-top: 6px;
        }
        .live-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            color: #ffffff;
            background: rgba(45,212,191,0.12);
            border: 1px solid rgba(45,212,191,0.16);
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 0.95rem;
        }
        .live-dot {
            width: 10px;
            height: 10px;
            background: #2DD4BF;
            border-radius: 999px;
            box-shadow: 0 0 0 6px rgba(45,212,191,0.08);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


st.set_page_config(page_title="CorrelSOC SOC Console", layout="wide")
render_header()
st.markdown(
    "<div style='display:flex; justify-content:space-between; align-items:flex-start; gap:24px;'>"
    "<div><h1 class='title'>CorrelSOC Security Console</h1>"
    "<div class='section-subtitle'>Live incident triage, correlation, and response monitoring for SOC analysts.</div></div>"
    "<div class='live-pill'><span class='live-dot'></span>Live pipeline connected</div>"
    "</div>",
    unsafe_allow_html=True,
)

if st.button("Run pipeline"):
    with st.spinner("Executing pipeline..."):
        subprocess.run([sys.executable, str(PIPELINE_PATH)], cwd=str(ROOT))

sample_logs = load_json(DATA_DIR / "sample_logs.json")
incidents_output = load_json(DATA_DIR / "incidents_output.json")
eval_results = load_json(EVAL_DIR / "results.json")

candidate_incidents = incidents_output.get("candidate_incidents", []) if incidents_output else []
triage_results = incidents_output.get("triage_results", []) if incidents_output else []
response_results = incidents_output.get("response_results", []) if incidents_output else []
correlation_result = incidents_output.get("correlation_result", {}) if incidents_output else {}
metadata = incidents_output.get("metadata", {}) if incidents_output else {}

if not incidents_output:
    st.markdown("<div class='soc-card'><h3>Pipeline status</h3><p>No pipeline output found. Run the pipeline to load incident data.</p></div>", unsafe_allow_html=True)
    st.stop()

severity_counts = None
if triage_results:
    df_triage = build_table(triage_results)
    if "severity" in df_triage.columns:
        severity_counts = (
            df_triage["severity"].value_counts().reindex(["Critical", "High", "Medium", "Low", "Benign"]).fillna(0).reset_index()
        )
        severity_counts.columns = ["severity", "count"]

flag_counts = {}
for incident in candidate_incidents:
    flags = incident.get("flags", [])
    for flag in flags:
        flag_counts[flag] = flag_counts.get(flag, 0) + 1

status_cards = [
    {"title": "Candidate incidents", "value": len(candidate_incidents), "meta": "Clusters identified"},
    {"title": "Triage assessments", "value": len(triage_results), "meta": "Incident classifications"},
    {"title": "Response actions", "value": len(response_results), "meta": "Remediation outputs"},
]

st.markdown("<div class='soc-card'><div class='content-row'>" + "".join(
    f"<div class='metric-card'><small>{card['meta']}</small><div class='value'>{card['value']}</div><div style='margin-top:8px;color:#94A3B8;'>{card['title']}</div></div>" for card in status_cards
) + "</div></div>", unsafe_allow_html=True)

st.markdown("<div class='grid-two'>", unsafe_allow_html=True)
with st.container():
    st.markdown("<div class='soc-card'><h3>Incident triage feed</h3><div class='table-section'>", unsafe_allow_html=True)
    if triage_results:
        display_triage = build_table(triage_results)[["incident_id", "mitre_attack_id", "mitre_technique_name", "severity", "confidence"]].head(12)
        display_triage["severity"] = display_triage["severity"].apply(lambda v: get_severity_badge(v))
        st.write(display_triage.to_html(index=False, classes='flat-table', escape=False), unsafe_allow_html=True)
    else:
        st.markdown("<p>No triage results available.</p>", unsafe_allow_html=True)
    st.markdown("</div></div>", unsafe_allow_html=True)

with st.container():
    st.markdown("<div class='soc-card'><h3>Live event stream</h3><div class='table-section'>", unsafe_allow_html=True)
    if sample_logs:
        display_logs = build_table(sample_logs)[["timestamp", "source_ip", "dest_ip", "event_type", "status"]].head(10)
        st.write(display_logs.to_html(index=False, classes='flat-table', escape=False), unsafe_allow_html=True)
    else:
        st.markdown("<p>No log events available.</p>", unsafe_allow_html=True)
    st.markdown("</div></div>", unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)

st.markdown("<div class='grid-two'>", unsafe_allow_html=True)
with st.container():
    st.markdown("<div class='soc-card'><h3>Security posture</h3><div class='content-row'>", unsafe_allow_html=True)
    if severity_counts is not None:
        fig = px.bar(
            severity_counts,
            x="severity",
            y="count",
            color="severity",
            color_discrete_map=SEVERITY_PALETTE,
            text="count",
        )
        fig.update_traces(marker_line_width=0, textposition="outside")
        fig.update_layout(
            plot_bgcolor="#0B0E11",
            paper_bgcolor="#151920",
            font_color="#E2E8F0",
            margin=dict(l=0, r=0, t=10, b=0),
            xaxis=dict(showgrid=False, tickfont=dict(color="#E2E8F0")),
            yaxis=dict(showgrid=False, tickfont=dict(color="#E2E8F0")),
            showlegend=False,
            bargap=0.3,
        )
        st.plotly_chart(fig, use_container_width=True, theme=None)
    else:
        st.markdown("<p>No severity data available.</p>", unsafe_allow_html=True)
    st.markdown("</div></div>", unsafe_allow_html=True)

with st.container():
    st.markdown("<div class='soc-card'><h3>Agent pipeline</h3><div class='content-row'>", unsafe_allow_html=True)
    pipeline_steps = [
        ("search", "Triage", "Analyze signals and tag incidents with ATT&CK.", True),
        ("radar", "Correlation", "Detect multi-stage attack chains across incidents.", False),
        ("upload-cloud", "Response", "Generate remediation actions and investigation steps.", False),
    ]
    for icon, title, desc, active in pipeline_steps:
        accent = "#2DD4BF" if active else "#94A3B8"
        st.markdown(
            f"<div style='flex:1 1 100%; border:1px solid #252B33; padding:16px; border-radius:4px; background:#11161D;'>"
            f"<div style='display:flex; align-items:center; gap:10px; margin-bottom:10px;'>{svg_icon(icon, accent)}<strong style='color:#E2E8F0;'>{title}</strong></div>"
            f"<div style='color:#94A3B8; font-size:0.95rem;'>{desc}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )
    st.markdown("</div></div>", unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)

st.markdown("<div class='soc-card'><h3>Evaluation summary</h3><div class='content-row'>", unsafe_allow_html=True)
if eval_results:
    metrics = eval_results.get("metrics", {})
    summary = metrics.get("summary", {})
    stat_cards = [
        ("Weighted Precision", f"{summary.get('precision_weighted', 0.0):.2f}"),
        ("Weighted Recall", f"{summary.get('recall_weighted', 0.0):.2f}"),
        ("Weighted F1", f"{summary.get('f1_weighted', 0.0):.2f}"),
        ("False Positive Rate", f"{metrics.get('false_positive_rate', 0.0):.2%}"),
    ]
    for title, value in stat_cards:
        st.markdown(
            f"<div class='metric-card'><small>{title}</small><div class='value'>{value}</div></div>",
            unsafe_allow_html=True,
        )
else:
    st.markdown("<p>No evaluation results available.</p>", unsafe_allow_html=True)
st.markdown("</div></div>", unsafe_allow_html=True)

st.markdown(
    "<div class='soc-card'><h3>Quick run instructions</h3><p style='color:#94A3B8; line-height:1.6;'>Use the button above to refresh the pipeline data. For a full deployment experience, run the Streamlit console locally or in Docker.</p></div>",
    unsafe_allow_html=True,
)
