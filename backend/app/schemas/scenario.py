from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.domain.enums import ScenarioDifficulty


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HostDefinition(StrictModel):
    hostname: str = Field(min_length=1, max_length=120)
    role: str = Field(min_length=1, max_length=80)
    operating_system: str = Field(min_length=1, max_length=120)
    public_facing: bool = False


class UserDefinition(StrictModel):
    username: str = Field(min_length=1, max_length=120)
    display_name: str = Field(min_length=1, max_length=160)
    department: str = Field(min_length=1, max_length=120)
    privileged: bool = False


class AssetDefinition(StrictModel):
    asset_id: str = Field(min_length=1, max_length=120)
    hostname: str = Field(min_length=1, max_length=120)
    criticality: Literal["low", "medium", "high", "critical"]
    tags: list[str] = Field(default_factory=list)


class EnvironmentDefinition(StrictModel):
    hosts: list[HostDefinition] = Field(min_length=1)
    users: list[UserDefinition] = Field(default_factory=list)
    assets: list[AssetDefinition] = Field(default_factory=list)


class AlertDefinition(StrictModel):
    alert_key: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=200)
    severity: Literal["informational", "low", "medium", "high", "critical"]
    source: str = Field(min_length=1, max_length=80)
    offset_seconds: int = Field(ge=0)
    details: dict[str, Any] = Field(default_factory=dict)


class AttackStageDefinition(StrictModel):
    stage_key: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=160)
    technique_ids: list[str] = Field(default_factory=list)
    offset_seconds: int = Field(ge=0)
    alert_keys: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)


class AttackChainDefinition(StrictModel):
    chain_id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    stages: list[AttackStageDefinition] = Field(min_length=1)


class BackgroundNoiseDefinition(StrictModel):
    events_per_minute: int = Field(default=30, ge=0, le=10000)
    sources: list[str] = Field(default_factory=list)
    benign_lookalikes: bool = True


class ExpectedAction(StrictModel):
    action_type: str = Field(min_length=1, max_length=80)
    target_pattern: str = Field(min_length=1, max_length=200)
    required: bool = True


class GroundTruthDefinition(StrictModel):
    expected_verdict: Literal["true_positive", "false_positive"]
    expected_severity: Literal["informational", "low", "medium", "high", "critical"]
    correlated_chain_ids: list[str] = Field(default_factory=list)
    expected_actions: list[ExpectedAction] = Field(default_factory=list)
    rubric: dict[str, float] = Field(default_factory=dict)

    @field_validator("rubric")
    @classmethod
    def rubric_weights_must_be_valid(cls, values: dict[str, float]) -> dict[str, float]:
        if any(weight < 0 for weight in values.values()):
            raise ValueError("Rubric weights must be zero or greater")
        return values


class ScenarioConstraints(StrictModel):
    min_duration_seconds: int = Field(default=300, ge=60)
    max_duration_seconds: int = Field(default=7200, ge=60)
    requires_evidence_for_containment: bool = True


class ScenarioDefinition(StrictModel):
    schema_version: Literal["1.0"]
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,119}$")
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    difficulty: ScenarioDifficulty
    estimated_duration_minutes: int = Field(ge=1, le=480)
    environment: EnvironmentDefinition
    attack_chains: list[AttackChainDefinition] = Field(default_factory=list)
    alerts: list[AlertDefinition] = Field(default_factory=list)
    background_noise: BackgroundNoiseDefinition = Field(default_factory=BackgroundNoiseDefinition)
    ground_truth: GroundTruthDefinition
    constraints: ScenarioConstraints = Field(default_factory=ScenarioConstraints)

    @field_validator("constraints")
    @classmethod
    def duration_bounds_must_be_ordered(
        cls, value: ScenarioConstraints
    ) -> ScenarioConstraints:
        if value.min_duration_seconds > value.max_duration_seconds:
            raise ValueError("Minimum duration cannot exceed maximum duration")
        return value

    @model_validator(mode="after")
    def validate_references(self) -> "ScenarioDefinition":
        hostnames = {host.hostname for host in self.environment.hosts}
        asset_hosts = {asset.hostname for asset in self.environment.assets}
        if missing_hosts := asset_hosts - hostnames:
            missing = ", ".join(sorted(missing_hosts))
            raise ValueError(f"Assets reference undefined hosts: {missing}")

        alert_keys = [alert.alert_key for alert in self.alerts]
        if len(alert_keys) != len(set(alert_keys)):
            raise ValueError("Alert keys must be unique")
        known_alerts = set(alert_keys)
        referenced_alerts = {
            alert_key
            for chain in self.attack_chains
            for stage in chain.stages
            for alert_key in stage.alert_keys
        }
        if missing_alerts := referenced_alerts - known_alerts:
            raise ValueError(
                f"Attack stages reference undefined alerts: {', '.join(sorted(missing_alerts))}"
            )

        chain_ids = [chain.chain_id for chain in self.attack_chains]
        if len(chain_ids) != len(set(chain_ids)):
            raise ValueError("Attack chain IDs must be unique")
        unknown_chains = set(self.ground_truth.correlated_chain_ids) - set(chain_ids)
        if unknown_chains:
            missing = ", ".join(sorted(unknown_chains))
            raise ValueError(
                f"Ground truth references undefined attack chains: {missing}"
            )
        return self
