import json
import random
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()

EVENT_TYPES = [
    "login",
    "logout",
    "file_access",
    "network_connection",
    "privilege_change",
    "data_transfer",
    "process_start",
]

STATUS_OPTIONS = ["success", "failure"]
ASSETS = ["web-server-1", "db-server-1", "workstation-1", "internal-file-server", "finance-app"]
USERS = ["alice", "bob", "charlie", "david", "eve"]

ATTACK_TYPES = ["brute_force", "port_scan", "data_exfiltration", "privilege_escalation", "benign"]


def make_base_event(timestamp, source_ip, dest_ip, user, event_type, status, asset, raw_message):
    return {
        "timestamp": timestamp.isoformat(),
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "user": user,
        "event_type": event_type,
        "status": status,
        "asset": asset,
        "raw_message": raw_message,
    }


def generate_benign_event(timestamp):
    source_ip = fake.ipv4_private()
    dest_ip = fake.ipv4_private()
    user = random.choice(USERS)
    event_type = random.choice(["login", "logout", "network_connection", "file_access", "process_start"])
    status = "success"
    asset = random.choice(ASSETS)
    raw_message = f"{user} performed {event_type} on {asset}"
    return make_base_event(timestamp, source_ip, dest_ip, user, event_type, status, asset, raw_message)


def generate_brute_force(timestamp, count=8):
    source_ip = fake.ipv4_public()
    target_user = random.choice(USERS)
    asset = random.choice(ASSETS)
    base_time = timestamp
    events = []
    for i in range(count):
        event_time = base_time + timedelta(seconds=random.randint(0, 50))
        raw_message = f"Failed login attempt for {target_user} on {asset} from {source_ip}"
        events.append(make_base_event(event_time, source_ip, fake.ipv4_private(), target_user, "login", "failure", asset, raw_message))
    return events


def generate_port_scan(timestamp, count=6):
    source_ip = fake.ipv4_public()
    events = []
    for i in range(count):
        event_time = timestamp + timedelta(seconds=random.randint(0, 55))
        asset = random.choice(ASSETS)
        dest_port = random.choice([22, 80, 443, 3389, 8080, 3306])
        dest_ip = f"192.168.1.{random.randint(2, 254)}"
        raw_message = f"Port scan from {source_ip} to {dest_ip}:{dest_port} on {asset}"
        events.append(make_base_event(event_time, source_ip, dest_ip, "unknown", "network_connection", "failure", asset, raw_message))
    return events


def generate_data_exfiltration(timestamp):
    source_ip = fake.ipv4_private()
    asset = random.choice(["db-server-1", "internal-file-server", "finance-app"])
    user = random.choice(USERS)
    event_time = timestamp
    dest_ip = fake.ipv4_public()
    raw_message = f"Large data transfer from {asset} to external destination {dest_ip} by {user}"
    event = make_base_event(event_time, source_ip, dest_ip, user, "data_transfer", "success", asset, raw_message)
    event["bytes_transferred"] = random.randint(800_000_000, 1_200_000_000)
    return [event]


def generate_privilege_escalation(timestamp):
    source_ip = fake.ipv4_private()
    user = random.choice(USERS)
    asset = random.choice(ASSETS)
    login_time = timestamp
    escal_time = timestamp + timedelta(minutes=random.randint(1, 4))
    events = [
        make_base_event(login_time, source_ip, fake.ipv4_private(), user, "login", "success", asset, f"Successful login for {user} on {asset}"),
        make_base_event(escal_time, source_ip, fake.ipv4_private(), user, "privilege_change", "success", asset, f"User {user} elevated privileges on {asset}"),
    ]
    return events


def generate_events(num_events=200, output_path="data/sample_logs.json"):
    events = []
    now = datetime.utcnow()
    current_time = now - timedelta(hours=2)
    event_count = 0

    while event_count < num_events:
        scenario = random.choices(
            ATTACK_TYPES,
            weights=[0.25, 0.15, 0.1, 0.1, 0.4],
            k=1,
        )[0]
        if scenario == "brute_force" and event_count + 8 <= num_events:
            batch = generate_brute_force(current_time)
        elif scenario == "port_scan" and event_count + 6 <= num_events:
            batch = generate_port_scan(current_time)
        elif scenario == "data_exfiltration" and event_count + 1 <= num_events:
            batch = generate_data_exfiltration(current_time)
        elif scenario == "privilege_escalation" and event_count + 2 <= num_events:
            batch = generate_privilege_escalation(current_time)
        else:
            batch = [generate_benign_event(current_time)]

        events.extend(batch)
        event_count = len(events)
        current_time += timedelta(seconds=random.randint(15, 120))

    events = sorted(events, key=lambda x: x["timestamp"])
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(events[:num_events], f, indent=2)

    print(f"Generated {len(events[:num_events])} events to {output_path}")


if __name__ == "__main__":
    generate_events(200)
