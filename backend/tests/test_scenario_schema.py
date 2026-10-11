from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.scenario import ScenarioDefinition
from app.schemas.scenario_io import load_scenario


def valid_scenario() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "id": "starter-phishing",
        "title": "Starter phishing investigation",
        "difficulty": "beginner",
        "estimated_duration_minutes": 30,
        "environment": {
            "hosts": [
                {
                    "hostname": "WS-014",
                    "role": "workstation",
                    "operating_system": "Windows 11",
                }
            ]
        },
        "ground_truth": {
            "expected_verdict": "true_positive",
            "expected_severity": "high",
        },
    }


def test_scenario_definition_validates_defaults() -> None:
    scenario = ScenarioDefinition.model_validate(valid_scenario())

    assert scenario.id == "starter-phishing"
    assert scenario.background_noise.events_per_minute == 30
    assert scenario.constraints.requires_evidence_for_containment is True


def test_scenario_definition_rejects_unknown_fields() -> None:
    payload = valid_scenario()
    payload["unexpected"] = True

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ScenarioDefinition.model_validate(payload)


def test_scenario_definition_rejects_invalid_duration_bounds() -> None:
    payload = valid_scenario()
    payload["constraints"] = {
        "min_duration_seconds": 900,
        "max_duration_seconds": 300,
    }

    with pytest.raises(ValidationError, match="Minimum duration cannot exceed maximum"):
        ScenarioDefinition.model_validate(payload)


def test_scenario_definition_rejects_dangling_ground_truth_chain() -> None:
    payload = valid_scenario()
    payload["ground_truth"]["correlated_chain_ids"] = ["missing-chain"]  # type: ignore[index]

    with pytest.raises(ValidationError, match="Ground truth references undefined"):
        ScenarioDefinition.model_validate(payload)


def test_example_yaml_loads_and_validates() -> None:
    scenario_path = Path(__file__).parents[1] / "examples" / "starter-phishing.yaml"

    scenario = load_scenario(scenario_path)

    assert scenario.id == "starter-phishing"
