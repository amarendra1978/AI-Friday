"""Input and Output Guardrails implementing validation, injection checks, and grounding."""

import html
import re
import yaml
from pathlib import Path
from pydantic import BaseModel, Field
from security.pii import detect_and_redact_pii

CONFIG_PATH = Path(__file__).parent / "guardrails.yaml"


class GuardrailResult(BaseModel):
    passed: bool
    flags: list[str] = Field(default_factory=list)
    sanitized_text: str
    severity: str = "LOW"  # LOW, MEDIUM, HIGH, BLOCK


def _load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}


class InputGuardrail:
    def __init__(self):
        self.config = _load_config()

    def validate(self, text: str, days: int = 3, budget: float = 1000.0, destination: str = "Paris") -> GuardrailResult:
        flags = []
        severity = "LOW"
        limits = self.config.get("input_limits", {})

        # 1. HTML Sanitization and Control Character Stripping
        sanitized = html.escape(text)
        sanitized = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", sanitized)

        # 2. Length and Range Checks
        max_len = limits.get("max_text_length", 1500)
        if len(sanitized) > max_len:
            flags.append("EXCEEDS_MAX_LENGTH")
            sanitized = sanitized[:max_len]

        if not (limits.get("min_days", 1) <= days <= limits.get("max_days", 14)):
            flags.append("INVALID_DAY_RANGE")
            return GuardrailResult(passed=False, flags=flags, sanitized_text=sanitized, severity="BLOCK")

        if not (limits.get("min_budget", 100.0) <= budget <= limits.get("max_budget", 100000.0)):
            flags.append("INVALID_BUDGET_RANGE")
            return GuardrailResult(passed=False, flags=flags, sanitized_text=sanitized, severity="BLOCK")

        allowed_destinations = limits.get("allowed_destinations", ["Paris", "Tokyo", "Jaipur"])
        if destination not in allowed_destinations:
            flags.append("UNSUPPORTED_DESTINATION")
            return GuardrailResult(passed=False, flags=flags, sanitized_text=sanitized, severity="BLOCK")

        # 3. Prompt Injection Detection
        lowered = sanitized.lower()
        for pattern in self.config.get("injection_patterns", []):
            if pattern.lower() in lowered:
                flags.append("PROMPT_INJECTION_ATTEMPT")
                return GuardrailResult(passed=False, flags=flags, sanitized_text=sanitized, severity="BLOCK")

        # 4. Unsafe / Illegal Intent
        for pattern in self.config.get("unsafe_intent_patterns", []):
            if pattern.lower() in lowered:
                flags.append("UNSAFE_INTENT_DETECTED")
                return GuardrailResult(passed=False, flags=flags, sanitized_text=sanitized, severity="BLOCK")

        # 5. PII Detection and Redaction
        sanitized, pii_flags = detect_and_redact_pii(sanitized)
        flags.extend(pii_flags)

        return GuardrailResult(
            passed=True,
            flags=flags,
            sanitized_text=sanitized,
            severity="MEDIUM" if pii_flags else "LOW",
        )


class OutputGuardrail:
    def validate_grounding(self, itinerary_data: dict, valid_places: list[dict]) -> GuardrailResult:
        """Grounding check: verifies place names exist in destinations.json."""
        flags = []
        valid_names = {p["name"].lower() for p in valid_places}
        hallucinated_places = []

        for day in itinerary_data.get("days", []):
            for activity in day.get("activities", []):
                place_name = activity.get("place_name", "")
                if place_name and place_name.lower() not in valid_names:
                    hallucinated_places.append(place_name)

        if hallucinated_places:
            flags.append(f"GROUNDING_HALLUCINATION: {', '.join(hallucinated_places)}")

        # Append mandatory disclaimer
        disclaimer = "\n\n*Note: Verify visa rules, advisories, opening hours, and prices with official sources before travel.*"

        return GuardrailResult(
            passed=len(hallucinated_places) == 0,
            flags=flags,
            sanitized_text=disclaimer,
            severity="MEDIUM" if hallucinated_places else "LOW",
        )