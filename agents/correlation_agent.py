import json
import os
from typing import Any

from anthropic import AI_PROMPT, Anthropic, HUMAN_PROMPT
from pydantic import BaseModel, ValidationError


class CorrelationOutput(BaseModel):
    chain_id: str
    related_incident_ids: list[str]
    is_multi_stage_attack: bool
    attack_narrative: str
    combined_severity: str


class CorrelationAgent:
    MODEL = "claude-sonnet-4-6"
    SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]

    PROMPT_TEMPLATE = """You are an attack correlation assistant.
Given multiple triaged incidents from the same time period, identify whether they form a multi-stage attack chain.
Return only valid JSON with fields: chain_id, related_incident_ids, is_multi_stage_attack, attack_narrative, combined_severity.

Incidents:
{incidents}
"""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.client = Anthropic(api_key=self.api_key) if self.api_key else None
        self.use_api = bool(self.client)

    def _build_prompt(self, incidents: list[dict[str, Any]]) -> str:
        return self.PROMPT_TEMPLATE.replace("{incidents}", json.dumps(incidents, indent=2))

    def _heuristic_fallback(self, incidents: list[dict[str, Any]]) -> CorrelationOutput:
        ids = [incident["incident_id"] for incident in incidents]
        descriptions = [incident["mitre_technique_name"] for incident in incidents]
        severity = max(incident["severity"] for incident in incidents)
        is_multi = len(incidents) > 1
        narrative = (
            " -> ".join(descriptions)
            if is_multi
            else f"Single incident: {descriptions[0]}"
        )
        return CorrelationOutput(
            chain_id="chain_1",
            related_incident_ids=ids,
            is_multi_stage_attack=is_multi,
            attack_narrative=f"Potential attack chain: {narrative}",
            combined_severity=severity,
        )

    def correlate(self, incidents: list[dict[str, Any]]) -> CorrelationOutput:
        if not incidents:
            return CorrelationOutput(
                chain_id="chain_0",
                related_incident_ids=[],
                is_multi_stage_attack=False,
                attack_narrative="No incidents to correlate.",
                combined_severity="Low",
            )

        if not self.use_api:
            return self._heuristic_fallback(incidents)

        prompt = self._build_prompt(incidents)
        response = self.client.completions.create(
            model=self.MODEL,
            prompt=f"{HUMAN_PROMPT}{prompt}{AI_PROMPT}",
            max_tokens=300,
            temperature=0.2,
        )
        text = response["completion"] if isinstance(response, dict) else getattr(response, "completion", "")
        data = self._parse_json(text)
        if data is None:
            return self._heuristic_fallback(incidents)
        return data

    def _parse_json(self, text: str) -> CorrelationOutput | None:
        try:
            payload = json.loads(text.strip())
            return CorrelationOutput(**payload)
        except (json.JSONDecodeError, ValidationError):
            return None
