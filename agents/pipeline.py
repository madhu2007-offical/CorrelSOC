import json
import os
import sys
from pathlib import Path
from time import perf_counter
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from pydantic import BaseModel

from agents.triage_agent import TriageAgent, TriageOutput
from agents.correlation_agent import CorrelationAgent, CorrelationOutput
from agents.response_agent import ResponseAgent, ResponseOutput


class PipelineResult(BaseModel):
    candidate_incidents: list[dict[str, Any]]
    triage_results: list[TriageOutput]
    correlation_result: CorrelationOutput
    response_results: list[ResponseOutput]
    metadata: dict[str, Any]


def import_correlation_module() -> None:
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(data: Any, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def run_pipeline(sample_log_path: Path | str, output_path: Path | str) -> PipelineResult:
    import_correlation_module()
    from correlation.correlator import load_events, cluster_events

    events = load_events(str(sample_log_path))
    candidate_incidents = [incident.__dict__ for incident in cluster_events(events)]

    triage_agent = TriageAgent(api_key=os.getenv("ANTHROPIC_API_KEY"))
    triage_results = [
        triage_agent.triage(candidate).model_dump() for candidate in candidate_incidents
    ]

    correlation_agent = CorrelationAgent(api_key=os.getenv("ANTHROPIC_API_KEY"))
    correlation_result = correlation_agent.correlate(triage_results)

    response_agent = ResponseAgent(api_key=os.getenv("ANTHROPIC_API_KEY"))
    response_results = [
        response_agent.respond({**triage_result}) for triage_result in triage_results
    ]

    pipeline_result = PipelineResult(
        candidate_incidents=candidate_incidents,
        triage_results=triage_results,
        correlation_result=correlation_result,
        response_results=response_results,
        metadata={
            "model": "claude-sonnet-4-6",
            "use_api": bool(os.getenv("ANTHROPIC_API_KEY")),
            "batch_size": len(candidate_incidents),
        },
    )

    save_json(pipeline_result.model_dump(), Path(output_path))
    return pipeline_result


def main():
    root = Path(__file__).resolve().parents[1]
    sample_logs = root / "data" / "sample_logs.json"
    output_path = root / "data" / "incidents_output.json"
    start = perf_counter()
    result = run_pipeline(sample_logs, output_path)
    elapsed = perf_counter() - start
    print(f"Pipeline completed in {elapsed:.2f}s")
    print(f"Wrote {len(result.triage_results)} triaged incidents to {output_path}")


if __name__ == "__main__":
    main()
