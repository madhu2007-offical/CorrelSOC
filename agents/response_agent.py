import json
import os
from typing import Any

from anthropic import AI_PROMPT, Anthropic, HUMAN_PROMPT
from pydantic import BaseModel, ValidationError


class ResponseOutput(BaseModel):
    incident_id: str
    immediate_actions: list[str]
    investigation_steps: list[str]
    long_term_fix: str


class ResponseAgent:
    MODEL = "claude-sonnet-4-6"

    PROMPT_TEMPLATE = """You are a security response planner.
Given a correlated or triaged incident, generate a concise remediation and investigation playbook.
Return only valid JSON with fields: incident_id, immediate_actions, investigation_steps, long_term_fix.

Input:
{payload}
"""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.client = Anthropic(api_key=self.api_key) if self.api_key else None
        self.use_api = bool(self.client)

    def _build_prompt(self, payload: dict[str, Any]) -> str:
        return self.PROMPT_TEMPLATE.replace("{payload}", json.dumps(payload, indent=2))

    def _heuristic_fallback(self, payload: dict[str, Any]) -> ResponseOutput:
        incident_id = payload.get("incident_id", "unknown")
        actions = ["Isolate the affected asset.", "Reset credentials for impacted user accounts."]
        investigations = ["Review logs from the source and target systems.", "Verify whether lateral movement occurred."]
        fix = "Harden authentication policies, enforce MFA, and implement improved alerting for suspicious access."

        if payload.get("mitre_technique_name") == "Brute Force":
            actions = [
                "Block the source IP at the perimeter.",
                "Force password reset for the targeted account.",
            ]
            investigations = [
                "Audit failed login attempts and source behavior.",
                "Confirm whether additional accounts were targeted.",
            ]
            fix = "Enable account lockout thresholds and monitor repeated login failures."

        elif payload.get("mitre_technique_name") == "Network Service Scanning":
            actions = [
                "Block or rate-limit scanning source addresses.",
                "Review firewall rules for exposed services.",
            ]
            investigations = [
                "Inspect network flow logs and service access patterns.",
                "Validate whether the source is internal or external.",
            ]
            fix = "Restrict unnecessary services and apply network segmentation."

        elif payload.get("mitre_technique_name") == "Exfiltration Over C2 Channel":
            actions = [
                "Interrupt the data transfer channel.",
                "Quarantine the asset involved in the transfer.",
            ]
            investigations = [
                "Track all recent outbound transfers from the asset.",
                "Confirm the destination host and protocol details.",
            ]
            fix = "Enforce egress filtering and data loss prevention controls."

        elif payload.get("mitre_technique_name") == "Valid Accounts":
            actions = [
                "Review the account's recent privilege changes.", "Revoke unnecessary elevated rights immediately."]
            investigations = [
                "Confirm whether the privilege escalation was authorized.",
                "Inspect access logs for unusual user activity.",
            ]
            fix = "Implement least privilege, role reviews, and just-in-time access."

        return ResponseOutput(
            incident_id=incident_id,
            immediate_actions=actions,
            investigation_steps=investigations,
            long_term_fix=fix,
        )

    def respond(self, payload: dict[str, Any]) -> ResponseOutput:
        if not self.use_api:
            return self._heuristic_fallback(payload)

        prompt = self._build_prompt(payload)
        response = self.client.completions.create(
            model=self.MODEL,
            prompt=f"{HUMAN_PROMPT}{prompt}{AI_PROMPT}",
            max_tokens=250,
            temperature=0.2,
        )
        text = response["completion"] if isinstance(response, dict) else getattr(response, "completion", "")
        data = self._parse_json(text)
        if data is None:
            return self._heuristic_fallback(payload)
        return data

    def _parse_json(self, text: str) -> ResponseOutput | None:
        try:
            payload = json.loads(text.strip())
            return ResponseOutput(**payload)
        except (json.JSONDecodeError, ValidationError):
            return None
