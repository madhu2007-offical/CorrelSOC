import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from correlation.correlator import load_events, cluster_events
from agents.triage_agent import TriageAgent
from agents.correlation_agent import CorrelationAgent
from agents.response_agent import ResponseAgent


def handler(request):
    try:
        sample_logs = ROOT / "data" / "sample_logs.json"
        events = load_events(str(sample_logs))
        candidate_incidents = [incident.__dict__ for incident in cluster_events(events)]

        triage_agent = TriageAgent(api_key=os.getenv("ANTHROPIC_API_KEY"))
        triage_results = [triage_agent.triage(candidate).model_dump() for candidate in candidate_incidents]

        correlation_agent = CorrelationAgent(api_key=os.getenv("ANTHROPIC_API_KEY"))
        correlation_result = correlation_agent.correlate(triage_results).model_dump()

        response_agent = ResponseAgent(api_key=os.getenv("ANTHROPIC_API_KEY"))
        response_results = [response_agent.respond({**triage_result}).model_dump() for triage_result in triage_results]

        body = json.dumps({
            "candidate_incidents": candidate_incidents,
            "triage_results": triage_results,
            "correlation_result": correlation_result,
            "response_results": response_results,
            "metadata": {
                "deployed_on": "vercel",
                "use_api": bool(os.getenv("ANTHROPIC_API_KEY")),
            },
        })

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": body,
        }
    except Exception as exc:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(exc)}),
        }
