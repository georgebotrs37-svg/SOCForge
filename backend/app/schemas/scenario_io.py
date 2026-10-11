import json
from pathlib import Path
from typing import Any

import yaml

from app.schemas.scenario import ScenarioDefinition


def load_scenario(path: Path) -> ScenarioDefinition:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        payload: Any = yaml.safe_load(raw)
    elif path.suffix.lower() == ".json":
        payload = json.loads(raw)
    else:
        raise ValueError("Scenario files must use .yaml, .yml, or .json")
    return ScenarioDefinition.model_validate(payload)
