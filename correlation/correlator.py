import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

DEFAULT_WINDOW_MINUTES = 5
CANDIDATE_OUTPUT = Path(__file__).resolve().parents[0] / ".." / "data" / "candidate_incidents.json"


@dataclass
class CandidateIncident:
    incident_id: str
    source_ip: str
    user: str
    start_time: str
    end_time: str
    event_count: int
    flags: list
    supporting_stats: dict
    events: list


def load_events(input_path: str) -> pd.DataFrame:
    raw = json.loads(Path(input_path).read_text(encoding="utf-8"))
    df = pd.DataFrame(raw)
    if df.empty:
        return df

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    if "bytes_transferred" not in df.columns:
        df["bytes_transferred"] = 0
    df["dest_port"] = df["raw_message"].str.extract(r":(\d+)")[0].fillna("")
    df["bytes_transferred"] = pd.to_numeric(df["bytes_transferred"], errors="coerce").fillna(0)
    return df.sort_values("timestamp").reset_index(drop=True)


def build_asset_baseline(df: pd.DataFrame) -> dict:
    baseline = {}
    asset_stats = df[df["bytes_transferred"] > 0].groupby("asset")["bytes_transferred"].agg(["mean", "std"])
    for asset, row in asset_stats.iterrows():
        baseline[asset] = {
            "mean": float(row["mean"]),
            "std": float(row["std"] if not pd.isna(row["std"]) else 0),
        }
    return baseline


def cluster_events(df: pd.DataFrame, window_minutes: int = DEFAULT_WINDOW_MINUTES) -> list[CandidateIncident]:
    incidents = []
    baseline = build_asset_baseline(df)
    grouped = df.groupby(["source_ip", "user"], sort=False)
    cluster_id = 1

    for (source_ip, user), group in grouped:
        if group.empty:
            continue

        window = timedelta(minutes=window_minutes)
        group = group.sort_values("timestamp").reset_index(drop=True)

        current = [group.iloc[0]]
        start_time = group.iloc[0]["timestamp"]

        for row in group.iloc[1:].itertuples(index=False):
            row_time = row.timestamp
            if row_time <= start_time + window:
                current.append(row)
            else:
                if len(current) > 1:
                    incidents.append(create_candidate(current, baseline, cluster_id))
                    cluster_id += 1
                current = [row]
                start_time = row_time

        if len(current) > 1:
            incidents.append(create_candidate(current, baseline, cluster_id))
            cluster_id += 1

    return incidents


def create_candidate(rows: list, baseline: dict, cluster_id: int) -> CandidateIncident:
    events = []
    for row in rows:
        if hasattr(row, "_asdict"):
            events.append(row._asdict())
        else:
            events.append(row.to_dict())

    for event in events:
        if isinstance(event.get("timestamp"), str):
            event["timestamp"] = pd.to_datetime(event["timestamp"])

    start = min(event["timestamp"] for event in events)
    end = max(event["timestamp"] for event in events)
    event_count = len(events)

    for event in events:
        if isinstance(event["timestamp"], pd.Timestamp):
            event["timestamp"] = event["timestamp"].isoformat()
    login_failures = [e for e in events if e["event_type"] == "login" and e["status"] == "failure"]
    privilege_changes = [e for e in events if e["event_type"] == "privilege_change"]
    transfers = [e for e in events if e["event_type"] in {"data_transfer", "file_transfer"}]
    distinct_assets = len({e["asset"] for e in events})
    distinct_ports = len({e["dest_port"] for e in events if e["dest_port"]})
    total_transfer = sum(e.get("bytes_transferred", 0) for e in events)
    duration_seconds = (end - start).total_seconds()

    flags = []
    stats = {
        "event_count": event_count,
        "distinct_assets": distinct_assets,
        "distinct_ports": distinct_ports,
        "login_failures": len(login_failures),
        "privilege_changes": len(privilege_changes),
        "total_transfer_bytes": total_transfer,
        "duration_seconds": duration_seconds,
    }

    if duration_seconds > 0:
        stats["events_per_minute"] = round(event_count / (duration_seconds / 60), 2)
    else:
        stats["events_per_minute"] = float(event_count)

    if len(login_failures) >= 5 and stats["events_per_minute"] >= 5:
        flags.append("possible_brute_force")

    if (distinct_ports >= 3 or distinct_assets >= 3) and duration_seconds <= 60:
        flags.append("possible_port_scan")

    for transfer in transfers:
        asset = transfer["asset"]
        volume = float(transfer.get("bytes_transferred", 0))
        baseline_info = baseline.get(asset, {"mean": 0.0, "std": 0.0})
        threshold = baseline_info["mean"] + 2 * baseline_info["std"]
        if threshold <= 0:
            threshold = 500_000_000
        if volume > threshold:
            flags.append("possible_exfiltration")
            break

    if privilege_changes and any(e["event_type"] == "login" for e in events):
        flags.append("possible_privilege_escalation")

    if not flags:
        flags.append("suspicious_cluster")

    return CandidateIncident(
        incident_id=f"incident_{cluster_id}",
        source_ip=events[0]["source_ip"],
        user=events[0]["user"],
        start_time=start.isoformat(),
        end_time=end.isoformat(),
        event_count=event_count,
        flags=flags,
        supporting_stats=stats,
        events=events,
    )


def save_candidate_incidents(incidents: list[CandidateIncident], output_path: str | Path = CANDIDATE_OUTPUT) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump([asdict(incident) for incident in incidents], f, indent=2)
    return output_path


def main():
    source_path = Path(__file__).resolve().parents[0] / ".." / "data" / "sample_logs.json"
    source_path = source_path.resolve()
    df = load_events(str(source_path))
    incidents = cluster_events(df)
    output = save_candidate_incidents(incidents)
    print(f"Saved {len(incidents)} candidate incidents to {output}")


if __name__ == "__main__":
    main()
