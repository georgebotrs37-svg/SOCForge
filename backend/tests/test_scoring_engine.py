from app.schemas.api import ScoreSubmission
from app.scoring.engine import (
    ActionEvidence,
    ExpectedResponseAction,
    ScoreWeights,
    ScoringTruth,
    grade_submission,
    load_score_weights,
)


def scoring_truth() -> ScoringTruth:
    return ScoringTruth(
        expected_verdicts={"alert-a": "true_positive", "alert-b": "false_positive"},
        expected_severities={"alert-a": "critical", "alert-b": "low"},
        correlated_alert_groups=[["alert-a", "alert-c"]],
        expected_actions=[ExpectedResponseAction(action_type="isolate_host", target="WS-001")],
        key_entities=["WS-001", "j.smith", "198.51.100.12"],
        indicators_of_compromise=["198.51.100.12", "malware.example.test"],
        technique_ids=["T1059.001"],
    )


def complete_submission() -> ScoreSubmission:
    return ScoreSubmission(
        triage_verdicts={"alert-a": "true_positive", "alert-b": "false_positive"},
        severity_assessments={"alert-a": "critical", "alert-b": "low"},
        escalated_alert_ids=["alert-a"],
        correlated_alert_groups=[["alert-a", "alert-c"]],
        report={
            "summary": "A sufficiently detailed incident summary. " * 5,
            "timeline": [
                {"at": f"step-{index}", "description": "Observed related event in logs"}
                for index in range(3)
            ],
            "iocs": ["198.51.100.12", "malware.example.test"],
            "root_cause": (
                "The user opened a malicious attachment that started the execution chain. " * 2
            ),
            "impact": "Credential access and outbound transfer were observed on the endpoint. " * 2,
            "recommendations": [
                "Isolate impacted endpoint and validate the containment status.",
                "Reset affected credentials and review privileged sign-ins.",
                "Block confirmed indicators and hunt across neighboring systems.",
            ],
        },
    )


def test_weights_are_loaded_from_external_configuration() -> None:
    weights = load_score_weights()

    assert abs(sum(weights.model_dump().values()) - 1.0) < 1e-6


def test_weight_configuration_rejects_weights_that_do_not_sum_to_one() -> None:
    try:
        ScoreWeights(
            triage_accuracy=0.5,
            severity_assessment=0.1,
            escalation_decision=0.1,
            investigation_quality=0.1,
            response_correctness_and_timing=0.1,
            alert_correlation=0.1,
            report_quality=0.1,
        )
    except ValueError as error:
        assert "sum to 1.0" in str(error)
    else:
        raise AssertionError("Invalid weight configuration should be rejected")


def test_complete_investigation_receives_full_score() -> None:
    result = grade_submission(
        scoring_truth(),
        complete_submission(),
        actions=[ActionEvidence("isolate_host", "WS-001", 30, True)],
        successful_queries=[
            "index=windows host=WS-001",
            "index=windows user=j.smith",
            "index=proxy src_ip=198.51.100.12",
        ],
    )

    assert result.total == 100
    assert set(result.breakdown) == {
        "triage_accuracy",
        "severity_assessment",
        "escalation_decision",
        "investigation_quality",
        "response_correctness_and_timing",
        "alert_correlation",
        "report_quality",
    }


def test_actions_without_evidence_are_penalized() -> None:
    with_evidence = grade_submission(
        scoring_truth(),
        complete_submission(),
        actions=[ActionEvidence("isolate_host", "WS-001", 30, True)],
        successful_queries=["WS-001", "j.smith", "198.51.100.12"],
    )
    without_evidence = grade_submission(
        scoring_truth(),
        complete_submission(),
        actions=[ActionEvidence("isolate_host", "WS-001", 30, False)],
        successful_queries=["WS-001", "j.smith", "198.51.100.12"],
    )

    assert (
        without_evidence.breakdown["response_correctness_and_timing"]
        < with_evidence.breakdown["response_correctness_and_timing"]
    )
