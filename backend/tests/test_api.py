from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import QueryHistory, Score, SkillProgress


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        test_client.app.state.session_factory = session_factory
        yield test_client
    app.dependency_overrides.clear()
    engine.dispose()


def test_auth_shift_query_action_and_server_scoring_flow(client: TestClient) -> None:
    registration = client.post(
        "/api/v1/auth/register",
        json={
            "email": "analyst@example.org",
            "display_name": "SOC Analyst",
            "password": "A-strong-password-123",
            "role": "admin",
        },
    )
    assert registration.status_code == 422

    registration = client.post(
        "/api/v1/auth/register",
        json={
            "email": "analyst@example.org",
            "display_name": "SOC Analyst",
            "password": "A-strong-password-123",
        },
    )
    assert registration.status_code == 201, registration.text
    assert registration.json()["role"] == "trainee"
    assert "password_hash" not in registration.json()

    login = client.post(
        "/api/v1/auth/login",
        json={"email": "ANALYST@example.org", "password": "A-strong-password-123"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/api/v1/auth/me", headers=headers).json()["email"] == ("analyst@example.org")
    soc_settings_response = client.get("/api/v1/settings/soc", headers=headers)
    assert soc_settings_response.status_code == 200
    soc_settings = soc_settings_response.json()
    assert soc_settings["critical_alert_sla_seconds"] == 600
    assert soc_settings["max_query_rows"] == 100_000
    assert "sysmon" in soc_settings["log_sources"]
    assert "jwt_secret" not in soc_settings_response.text
    assert client.get("/api/v1/settings/soc").status_code == 401
    assert client.get("/health").headers["x-content-type-options"] == "nosniff"

    shift_response = client.post(
        "/api/v1/shifts",
        headers=headers,
        json={
            "template": "brute_force",
            "seed": 19,
            "duration_minutes": 5,
            "noise_events_per_minute": 0,
        },
    )
    assert shift_response.status_code == 201, shift_response.text
    shift = shift_response.json()
    shift_id = shift["id"]
    assert shift["log_count"] > 0
    assert shift["alert_count"] > 0
    assert "ground_truth" not in shift_response.text
    assert "expected_verdicts" not in shift_response.text

    alerts_response = client.get(f"/api/v1/shifts/{shift_id}/alerts", headers=headers)
    assert alerts_response.status_code == 200
    alerts = alerts_response.json()
    query_response = client.post(
        f"/api/v1/shifts/{shift_id}/query",
        headers=headers,
        json={"query": "index=windows event_id=4625 | stats count", "result_limit": 10},
    )
    assert query_response.status_code == 200
    assert query_response.json()["results"] == [{"count": 6}]

    primary_alert = next(alert for alert in alerts if alert["chain_id"] is not None)
    action_response = client.post(
        f"/api/v1/shifts/{shift_id}/actions",
        headers=headers,
        json={
            "action_type": "disable_account",
            "target": primary_alert["details"]["username"],
            "evidence_ids": [primary_alert["id"]],
        },
    )
    assert action_response.status_code == 201

    chain_alerts = [alert for alert in alerts if alert["chain_id"] is not None]
    submission = {
        "triage_verdicts": {
            alert["id"]: "true_positive" if alert["chain_id"] else "false_positive"
            for alert in alerts
        },
        "severity_assessments": {alert["id"]: alert["severity"] for alert in alerts},
        "escalated_alert_ids": [
            alert["id"] for alert in chain_alerts if alert["severity"] in {"high", "critical"}
        ],
        "correlated_alert_groups": [[alert["id"] for alert in chain_alerts]],
        "report": {
            "summary": (
                "Repeated failed authentication was followed by a successful "
                "privileged login."
            ),
            "timeline": [
                {"at": "12:00", "description": "Repeated failed remote login events observed."},
                {"at": "12:02", "description": "A successful remote login followed the failures."},
            ],
            "iocs": [],
            "root_cause": (
                "The account password was guessed and then used from an untrusted source."
            ),
            "impact": "A privileged session was established on the affected workstation.",
            "recommendations": ["Reset the account password and review related access."],
        },
    }
    score_response = client.post(
        f"/api/v1/shifts/{shift_id}/submit",
        headers=headers,
        json=submission,
    )
    assert score_response.status_code == 200
    score = score_response.json()
    assert 0 <= score["total"] <= 100
    assert "ground_truth" not in score_response.text
    assert "expected_actions" not in score_response.text
    assert (
        client.post(
            f"/api/v1/shifts/{shift_id}/query",
            headers=headers,
            json={"query": "index=windows"},
        ).status_code
        == 409
    )

    with client.app.state.session_factory() as session:
        assert session.scalar(select(Score).where(Score.shift_id == shift_id)) is not None
        assert (
            session.scalar(select(QueryHistory).where(QueryHistory.shift_id == shift_id))
            is not None
        )
        assert (
            session.scalar(
                select(SkillProgress).where(SkillProgress.user_id == registration.json()["id"])
            )
            is not None
        )


def test_password_failure_and_invalid_bearer_token_are_rejected(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "analyst@example.org",
            "display_name": "SOC Analyst",
            "password": "A-strong-password-123",
        },
    )
    bad_login = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.org", "password": "incorrect-password"},
    )
    assert bad_login.status_code == 401, bad_login.text
    assert (
        client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid"},
        ).status_code
        == 401
    )
