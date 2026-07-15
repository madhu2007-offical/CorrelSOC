import json
import os
from typing import Any

from anthropic import AI_PROMPT, Anthropic, HUMAN_PROMPT
from pydantic import BaseModel, Field, ValidationError


class TriageOutput(BaseModel):
    incident_id: str
    mitre_attack_id: str
    mitre_technique_name: str
    severity: str = Field(..., pattern="^(Low|Medium|High|Critical)$")
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str


class TriageAgent:
    MODEL = "claude-sonnet-4-6"
    SEVERITY_MAP = {
        "possible_brute_force": ("High", "T1110", "Brute Force"),
        "possible_port_scan": ("Medium", "T1046", "Network Service Scanning"),
        "possible_exfiltration": ("Critical", "T1041", "Exfiltration Over C2 Channel"),
        "possible_privilege_escalation": ("High", "T1078", "Valid Accounts"),
        "suspicious_cluster": ("Medium", "T1598", "Account Manipulation"),
    }

    PROMPT_TEMPLATE = """You are an incident triage assistant.
Map a grouped candidate incident cluster to a JSON object with the following fields:
incident_id, mitre_attack_id, mitre_technique_name, severity, confidence, reasoning.

Candidate cluster:
{candidate}

Return only valid JSON.
"""

    EXAMPLES = [
        {
            "candidate": {
                "incident_id": "incident_1",
                "flags": ["possible_brute_force"],
                "supporting_stats": {"login_failures": 8, "events_per_minute": 6.4},
                "events": [
                    {"event_type": "login", "status": "failure", "asset": "web-server-1"}
                ],
            },
            "output": {
                "incident_id": "incident_1",
                "mitre_attack_id": "T1110",
                "mitre_technique_name": "Brute Force",
                "severity": "High",
                "confidence": 0.92,
                "reasoning": "Multiple failed login attempts from a single source suggest an automated brute force attack.",
            },
        },
        {
            "candidate": {
                "incident_id": "incident_2",
                "flags": ["possible_port_scan"],
                "supporting_stats": {"distinct_ports": 5, "duration_seconds": 42},
                "events": [
                    {"event_type": "network_connection", "dest_ip": "10.0.0.10"}
                ],
            },
            "output": {
                "incident_id": "incident_2",
                "mitre_attack_id": "T1046",
                "mitre_technique_name": "Network Service Scanning",
                "severity": "Medium",
                "confidence": 0.85,
                "reasoning": "Rapid connections to many ports indicates an adversary scanning those services.",
            },
        },
    ]

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.client = Anthropic(api_key=self.api_key) if self.api_key else None
        self.use_api = bool(self.client)

    def _build_prompt(self, candidate: dict[str, Any]) -> str:
        examples_text = "\n\n".join(
            f"Candidate cluster:\n{json.dumps(example['candidate'], indent=2)}\nOutput:\n{json.dumps(example['output'], indent=2)}"
            for example in self.EXAMPLES
        )
        return f"{examples_text}\n\nCandidate cluster:\n{json.dumps(candidate, indent=2)}\nOutput:"

    def _heuristic_fallback(self, candidate: dict[str, Any]) -> TriageOutput:
        flags = candidate.get("flags", [])
        primary = flags[0] if flags else "suspicious_cluster"
        severity, attack_id, technique = self.SEVERITY_MAP.get(primary, self.SEVERITY_MAP["suspicious_cluster"])
        confidence = 0.9 if primary != "suspicious_cluster" else 0.65
        reasoning = f"Detected flags {flags}. This cluster appears to match {technique}."
        return TriageOutput(
            incident_id=candidate["incident_id"],
            mitre_attack_id=attack_id,
            mitre_technique_name=technique,
            severity=severity,
            confidence=confidence,
            reasoning=reasoning,
        )

    def triage(self, candidate: dict[str, Any]) -> TriageOutput:
        if not self.use_api:
            return self._heuristic_fallback(candidate)

        prompt = self._build_prompt(candidate)
        response = self.client.completions.create(
            model=self.MODEL,
            prompt=f"{HUMAN_PROMPT}{prompt}{AI_PROMPT}",
            max_tokens=250,
            temperature=0.2,
        )
        text = response["completion"] if isinstance(response, dict) else getattr(response, "completion", "")
        data = self._parse_json(text)
        if data is None:
            return self._heuristic_fallback(candidate)
        return data

    def _parse_json(self, text: str) -> TriageOutput | None:
        try:
            payload = json.loads(text.strip())
            return TriageOutput(**payload)
        except (json.JSONDecodeError, ValidationError):
            return None
