import json
import os
import sys
from pathlib import Path
from time import perf_counter

import pandas as pd
from sklearn.metrics import precision_recall_fscore_support


MODEL_TO_LABEL = {
    "T1110": "brute_force",
    "T1046": "port_scan",
    "T1041": "data_exfiltration",
    "T1078": "privilege_escalation",
}


def root_path() -> Path:
    return Path(__file__).resolve().parents[1]


def add_root_to_path() -> None:
    root = root_path()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))


def load_ground_truth(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def flatten_ground_truth(ground_truth: list[dict]) -> list[dict]:
    events = []
    for incident in ground_truth:
        for event in incident["events"]:
            event_copy = event.copy()
            event_copy["ground_incident_id"] = incident["incident_id"]
            event_copy["ground_label"] = incident["label"]
            events.append(event_copy)
    return sorted(events, key=lambda e: e["timestamp"])


def run_eval_pipeline(events: list[dict]) -> tuple[list[dict], list[dict]]:
    from agents.triage_agent import TriageAgent
    from correlation.correlator import load_events as load_json_events, cluster_events

    eval_path = root_path() / "eval" / "temp_eval_events.json"
    eval_path.write_text(json.dumps(events, indent=2), encoding="utf-8")
    df = load_json_events(str(eval_path))
    clusters = cluster_events(df)

    if not clusters:
        raw_events = df.to_dict(orient="records")
        clusters = []
        for idx, event in enumerate(raw_events, start=1):
            if isinstance(event.get("timestamp"), pd.Timestamp):
                event["timestamp"] = event["timestamp"].isoformat()
            clusters.append(
                {
                    "incident_id": f"incident_{idx}",
                    "source_ip": event.get("source_ip", "unknown"),
                    "user": event.get("user", "unknown"),
                    "start_time": event.get("timestamp"),
                    "end_time": event.get("timestamp"),
                    "event_count": 1,
                    "flags": ["suspicious_cluster"],
                    "supporting_stats": {
                        "event_count": 1,
                        "distinct_assets": 1,
                        "distinct_ports": 1 if event.get("dest_ip") else 0,
                        "login_failures": 1 if event.get("event_type") == "login" and event.get("status") == "failure" else 0,
                        "privilege_changes": 1 if event.get("event_type") == "privilege_change" else 0,
                        "total_transfer_bytes": float(event.get("bytes_transferred", 0) or 0),
                        "duration_seconds": 0.0,
                        "events_per_minute": 1.0,
                    },
                    "events": [event],
                }
            )

    triage_agent = TriageAgent(api_key=os.getenv("ANTHROPIC_API_KEY"))
    results = []
    for cluster in clusters:
        result = triage_agent.triage(cluster)
        results.append(result.model_dump())

    eval_path.unlink(missing_ok=True)
    return clusters, results


def predict_label(triage_result: dict) -> str:
    attack_id = triage_result.get("mitre_attack_id", "")
    return MODEL_TO_LABEL.get(attack_id, "benign")


def match_ground_truth(clusters: list[dict], ground_truth: list[dict]) -> list[tuple[dict, dict | None]]:
    matches = []
    for cluster in clusters:
        match = next(
            (
                truth
                for truth in ground_truth
                if cluster.get("source_ip") == truth["source_ip"] and cluster.get("user") == truth["user"]
            ),
            None,
        )
        matches.append((cluster, match))
    return matches


def evaluate_matches(matches: list[tuple[object, dict | None]], triage_results: list[dict]) -> dict:
    y_true = []
    y_pred = []
    labels = ["brute_force", "port_scan", "data_exfiltration", "privilege_escalation", "benign"]
    false_positives = 0
    benign_count = 0
    unmatched_false_positives = 0

    for (cluster, truth), result in zip(matches, triage_results):
        predicted = predict_label(result)
        if truth is None:
            if predicted != "benign":
                unmatched_false_positives += 1
            continue
        actual = truth["label"]
        y_true.append(actual)
        y_pred.append(predicted)
        if actual == "benign":
            benign_count += 1
            if predicted != "benign":
                false_positives += 1

    metrics = {label: {"precision": 0.0, "recall": 0.0, "f1": 0.0, "support": 0} for label in labels}
    summary = {"precision_weighted": 0.0, "recall_weighted": 0.0, "f1_weighted": 0.0}

    if y_true:
        precision, recall, f1, support = precision_recall_fscore_support(
            y_true,
            y_pred,
            labels=labels,
            average=None,
            zero_division=0,
        )
        metrics = {label: {"precision": float(precision[i]), "recall": float(recall[i]), "f1": float(f1[i]), "support": int(support[i])} for i, label in enumerate(labels)}
        summary = {
            "precision_weighted": float(precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)[0]),
            "recall_weighted": float(precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)[1]),
            "f1_weighted": float(precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)[2]),
        }

    return {
        "metrics": metrics,
        "summary": summary,
        "false_positive_rate": float(false_positives / benign_count) if benign_count else 0.0,
        "unmatched_false_positives": unmatched_false_positives,
    }


def estimate_cost_and_tokens(triage_results: list[dict], clusters: list[dict]) -> dict:
    total_text = 0
    for cluster, result in zip(clusters, triage_results):
        if hasattr(cluster, "__dict__"):
            candidate_text = json.dumps(cluster.__dict__)
        else:
            candidate_text = json.dumps(cluster)
        result_text = json.dumps(result)
        total_text += len(candidate_text) + len(result_text)

    tokens = int(total_text / 4)
    cost_per_1000 = (tokens / 1000) * 0.03
    return {
        "approximate_tokens": tokens,
        "estimated_cost_usd_per_1000_events": round(cost_per_1000, 4),
    }


def print_summary(metrics: dict, elapsed: float, batch_size: int, cost_estimate: dict) -> None:
    metric_values = metrics.get("metrics", metrics)
    summary = metrics.get("summary", {})
    false_positive_rate = metrics.get("false_positive_rate", 0.0)

    print("Evaluation Summary")
    print("------------------")
    print(f"Batch size: {batch_size}")
    print(f"Elapsed time: {elapsed:.3f}s")
    print(f"Approximate token usage: {cost_estimate['approximate_tokens']}")
    print(f"Estimated cost per 1000 events: ${cost_estimate['estimated_cost_usd_per_1000_events']}")
    print(f"False positive rate: {false_positive_rate:.2%}")
    print()
    for label, label_metrics in metric_values.items():
        print(f"{label}: precision={label_metrics['precision']:.2f}, recall={label_metrics['recall']:.2f}, f1={label_metrics['f1']:.2f}, support={label_metrics['support']}")
    print()
    print("Weighted summary:")
    print(f" Precision: {summary.get('precision_weighted', 0.0):.2f}")
    print(f" Recall: {summary.get('recall_weighted', 0.0):.2f}")
    print(f" F1: {summary.get('f1_weighted', 0.0):.2f}")


def main():
    add_root_to_path()
    root = root_path()
    ground_truth_path = root / "eval" / "labeled_events.json"
    ground_truth = load_ground_truth(ground_truth_path)
    events = flatten_ground_truth(ground_truth)

    start = perf_counter()
    clusters, triage_results = run_eval_pipeline(events)
    elapsed = perf_counter() - start

    matches = match_ground_truth(clusters, ground_truth)
    metrics = evaluate_matches(matches, triage_results)
    cost_estimate = estimate_cost_and_tokens(triage_results, clusters)

    output_path = root / "eval" / "results.json"
    output_data = {
        "metrics": metrics,
        "batch_size": len(clusters),
        "elapsed_seconds": elapsed,
        "cost_estimate": cost_estimate,
        "pipeline_output_path": str(root / "data" / "incidents_output.json"),
    }
    Path(output_path).write_text(json.dumps(output_data, indent=2), encoding="utf-8")

    print_summary(metrics, elapsed, len(clusters), cost_estimate)
    print(f"Saved evaluation results to {output_path}")


if __name__ == "__main__":
    main()
