import json
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.schemas.api import ScoreSubmission

Verdict = Literal["true_positive", "false_positive"]
Severity = Literal["informational", "low", "medium", "high", "critical"]
_SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class ExpectedResponseAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: str
    target: str


class ScoringTruth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_verdicts: dict[str, Verdict]
    expected_severities: dict[str, Severity]
    correlated_alert_groups: list[list[str]]
    expected_actions: list[ExpectedResponseAction]
    key_entities: list[str]
    indicators_of_compromise: list[str]
    technique_ids: list[str]
    sla_seconds: int = Field(default=600, ge=1)


class ScoreWeights(BaseModel):
    model_config = ConfigDict(extra="forbid")

    triage_accuracy: float = Field(ge=0, le=1)
    severity_assessment: float = Field(ge=0, le=1)
    escalation_decision: float = Field(ge=0, le=1)
    investigation_quality: float = Field(ge=0, le=1)
    response_correctness_and_timing: float = Field(ge=0, le=1)
    alert_correlation: float = Field(ge=0, le=1)
    report_quality: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def weights_must_sum_to_one(self) -> "ScoreWeights":
        if abs(sum(self.model_dump().values()) - 1.0) > 1e-6:
            raise ValueError("Scoring weights must sum to 1.0")
        return self


@dataclass(frozen=True, slots=True)
class ActionEvidence:
    action_type: str
    target: str
    elapsed_seconds: int
    has_evidence: bool


@dataclass(frozen=True, slots=True)
class ScoreGrade:
    total: float
    breakdown: dict[str, float]
    feedback: dict[str, Any]


def load_score_weights() -> ScoreWeights:
    weights_path = Path(__file__).with_name("weights.json")
    try:
        content = weights_path.read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimeError(f"Unable to read scoring weights at {weights_path}") from error
    try:
        payload: object = json.loads(content)
        return ScoreWeights.model_validate(payload)
    except (json.JSONDecodeError, ValidationError) as error:
        raise RuntimeError("Scoring weights configuration is invalid") from error


def _f1(expected: set[tuple[str, str]], actual: set[tuple[str, str]]) -> float:
    if not expected and not actual:
        return 1.0
    if not expected or not actual:
        return 0.0
    true_positive = len(expected & actual)
    precision = true_positive / len(actual)
    recall = true_positive / len(expected)
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def _correlation_pairs(groups: list[list[str]]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for group in groups:
        for first, second in combinations(set(group), 2):
            left, right = sorted((first, second))
            pairs.add((left, right))
    return pairs


def _score_triage(truth: ScoringTruth, submission: ScoreSubmission) -> float:
    if not truth.expected_verdicts:
        return 1.0
    correct = sum(
        submission.triage_verdicts.get(alert_id) == verdict
        for alert_id, verdict in truth.expected_verdicts.items()
    )
    unknown = set(submission.triage_verdicts) - set(truth.expected_verdicts)
    return max(0.0, correct / len(truth.expected_verdicts) - 0.05 * len(unknown))


def _score_severity(truth: ScoringTruth, submission: ScoreSubmission) -> float:
    if not truth.expected_severities:
        return 1.0
    total = 0.0
    for alert_id, expected in truth.expected_severities.items():
        actual = submission.severity_assessments.get(alert_id)
        if actual is not None:
            distance = abs(_SEVERITY_RANK[expected] - _SEVERITY_RANK[actual])
            total += max(0.0, 1 - distance / 4)
    unknown = set(submission.severity_assessments) - set(truth.expected_severities)
    return max(0.0, total / len(truth.expected_severities) - 0.05 * len(unknown))


def _score_escalation(truth: ScoringTruth, submission: ScoreSubmission) -> float:
    expected = {
        alert_id
        for alert_id, severity in truth.expected_severities.items()
        if _SEVERITY_RANK[severity] >= _SEVERITY_RANK["high"]
        and truth.expected_verdicts.get(alert_id) == "true_positive"
    }
    actual = set(submission.escalated_alert_ids) & set(truth.expected_verdicts)
    return _f1(
        {(alert_id, "escalate") for alert_id in expected},
        {(alert_id, "escalate") for alert_id in actual},
    )


def _score_investigation(truth: ScoringTruth, query_texts: list[str]) -> float:
    expected = {item.casefold() for item in truth.key_entities if item}
    combined_queries = "\n".join(query_texts).casefold()
    coverage = (
        sum(entity in combined_queries for entity in expected) / len(expected) if expected else 1.0
    )
    successful_query_count = len(
        {query.strip().casefold() for query in query_texts if query.strip()}
    )
    pivot_diversity = min(successful_query_count / 3, 1.0)
    return 0.7 * coverage + 0.3 * pivot_diversity


def _score_response(
    truth: ScoringTruth,
    actions: list[ActionEvidence],
) -> float:
    expected = truth.expected_actions
    if not expected:
        return 1.0
    used_actions: set[int] = set()
    earned = 0.0
    for required in expected:
        for index, actual in enumerate(actions):
            if (
                index not in used_actions
                and actual.action_type == required.action_type
                and actual.target.casefold() == required.target.casefold()
            ):
                used_actions.add(index)
                timing = 1.0 if actual.elapsed_seconds <= truth.sla_seconds else 0.5
                evidence_factor = 1.0 if actual.has_evidence else 0.7
                earned += timing * evidence_factor
                break
    extra_actions = len(actions) - len(used_actions)
    return max(0.0, earned / len(expected) - 0.1 * extra_actions / len(expected))


def _score_report(truth: ScoringTruth, submission: ScoreSubmission) -> float:
    report = submission.report
    summary_score = min(len(report.summary.strip()) / 120, 1.0)
    timeline_score = min(
        sum(
            bool(item.at.strip() and len(item.description.strip()) >= 15)
            for item in report.timeline
        )
        / 3,
        1.0,
    )
    expected_iocs = {item.casefold() for item in truth.indicators_of_compromise}
    actual_iocs = {item.strip().casefold() for item in report.iocs if item.strip()}
    ioc_score = _f1(
        {(item, "ioc") for item in expected_iocs},
        {(item, "ioc") for item in actual_iocs},
    )
    root_cause_score = min(len(report.root_cause.strip()) / 120, 1.0)
    impact_score = min(len(report.impact.strip()) / 80, 1.0)
    recommendations_score = min(
        sum(len(item.strip()) >= 20 for item in report.recommendations) / 3,
        1.0,
    )
    return (
        0.15 * summary_score
        + 0.15 * timeline_score
        + 0.25 * ioc_score
        + 0.15 * root_cause_score
        + 0.1 * impact_score
        + 0.2 * recommendations_score
    )


def grade_submission(
    truth: ScoringTruth,
    submission: ScoreSubmission,
    *,
    actions: list[ActionEvidence],
    successful_queries: list[str],
    weights: ScoreWeights | None = None,
) -> ScoreGrade:
    configured_weights = weights or load_score_weights()
    dimensions = {
        "triage_accuracy": _score_triage(truth, submission),
        "severity_assessment": _score_severity(truth, submission),
        "escalation_decision": _score_escalation(truth, submission),
        "investigation_quality": _score_investigation(truth, successful_queries),
        "response_correctness_and_timing": _score_response(truth, actions),
        "alert_correlation": _f1(
            _correlation_pairs(truth.correlated_alert_groups),
            _correlation_pairs(submission.correlated_alert_groups),
        ),
        "report_quality": _score_report(truth, submission),
    }
    weights_by_dimension = configured_weights.model_dump()
    total = round(
        100
        * sum(dimensions[dimension] * weight for dimension, weight in weights_by_dimension.items()),
        2,
    )
    feedback = {
        dimension: "Good work" if score >= 0.8 else "Review this investigation skill"
        for dimension, score in dimensions.items()
    }
    return ScoreGrade(
        total=total,
        breakdown={dimension: round(score * 100, 2) for dimension, score in dimensions.items()},
        feedback=feedback,
    )
