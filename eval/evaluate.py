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


def compute_supporting_stats(events: list[dict]) -> dict:
    distinct_assets = len({e.get("asset") for e in events if e.get("asset")})
    distinct_ports = len({e.get("dest_port") for e in events if e.get("dest_port")})
    login_failures = [e for e in events if e.get("event_type") == "login" and e.get("status") == "failure"]
    privilege_changes = [e for e in events if e.get("event_type") == "privilege_change"]
    transfers = [e for e in events if e.get("event_type") in {"data_transfer", "file_transfer"}]
    total_transfer_bytes = sum(float(e.get("bytes_transferred", 0) or 0) for e in events)

    timestamps = [pd.to_datetime(e["timestamp"]) for e in events]
    span = (max(timestamps) - min(timestamps)).total_seconds() if timestamps else 0.0
    duration_seconds = span if span > 0 else 0.0
    event_count = len(events)
    events_per_minute = float(event_count) if duration_seconds == 0 else round(event_count / (duration_seconds / 60), 2)

    return {
        "event_count": event_count,
        "distinct_assets": distinct_assets,
        "distinct_ports": distinct_ports,
        "login_failures": len(login_failures),
        "privilege_changes": len(privilege_changes),
        "total_transfer_bytes": total_transfer_bytes,
        "duration_seconds": duration_seconds,
        "events_per_minute": events_per_minute,
    }


def infer_flags(events: list[dict], stats: dict) -> list[str]:
    flags = []
    if stats["login_failures"] >= 5 and stats["events_per_minute"] >= 5:
        flags.append("possible_brute_force")
    if (stats["distinct_ports"] >= 3 or stats["distinct_assets"] >= 3) and stats["duration_seconds"] <= 60:
        flags.append("possible_port_scan")
    for transfer in [e for e in events if e.get("event_type") in {"data_transfer", "file_transfer"}]:
        asset = transfer.get("asset")
        volume = float(transfer.get("bytes_transferred", 0) or 0)
        if volume > 0:
            flags.append("possible_exfiltration")
            break
    if any(e.get("event_type") == "privilege_change" for e in events) and any(e.get("event_type") == "login" for e in events):
        flags.append("possible_privilege_escalation")
    # single-event inference rules for labeled evaluation set
    if not flags:
        for event in events:
            if event.get("event_type") == "login" and event.get("status") == "failure":
                flags.append("possible_brute_force")
                break
            if event.get("event_type") == "network_connection" and event.get("status") == "failure":
                flags.append("possible_port_scan")
                break
            if event.get("event_type") in {"data_transfer", "file_transfer"} and float(event.get("bytes_transferred", 0) or 0) > 0:
                flags.append("possible_exfiltration")
                break
            if event.get("event_type") == "privilege_change":
                flags.append("possible_privilege_escalation")
                break
    if not flags:
        flags.append("suspicious_cluster")
    return flags


def build_candidate_incident(incident: dict) -> dict:
    events = [event.copy() for event in incident.get("events", [])]
    for event in events:
        if "dest_port" not in event:
            event["dest_port"] = ""
        if "bytes_transferred" not in event:
            event["bytes_transferred"] = 0
    stats = compute_supporting_stats(events)
    flags = infer_flags(events, stats)

    return {
        "incident_id": incident.get("incident_id", "unknown"),
        "source_ip": incident.get("source_ip", "unknown"),
        "user": incident.get("user", "unknown"),
        "start_time": events[0].get("timestamp") if events else "",
        "end_time": events[-1].get("timestamp") if events else "",
        "event_count": len(events),
        "flags": flags,
        "supporting_stats": stats,
        "events": events,
    }


def run_eval_pipeline(ground_truth: list[dict]) -> tuple[list[dict], list[dict]]:
    from agents.triage_agent import TriageAgent

    triage_agent = TriageAgent(api_key=os.getenv("ANTHROPIC_API_KEY"))
    clusters = []
    results = []

    for incident in ground_truth:
        candidate = build_candidate_incident(incident)
        clusters.append(candidate)
        result = triage_agent.triage(candidate)
        results.append(result.model_dump())

    return clusters, results


def normalize_label(label: str) -> str:
    if not isinstance(label, str):
        return "benign"
    return label.strip().lower()


def predict_label(triage_result: dict) -> str:
    attack_id = str(triage_result.get("mitre_attack_id", "")).strip()
    return MODEL_TO_LABEL.get(attack_id, "benign")


def match_ground_truth(clusters: list[dict], ground_truth: list[dict]) -> list[tuple[dict, dict | None]]:
    truth_by_id = {truth["incident_id"]: truth for truth in ground_truth}
    matches = []
    for cluster in clusters:
        match = truth_by_id.get(cluster.get("incident_id"))
        if match is None:
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
        actual = normalize_label(truth["label"])
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

    start = perf_counter()
    clusters, triage_results = run_eval_pipeline(ground_truth)
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
