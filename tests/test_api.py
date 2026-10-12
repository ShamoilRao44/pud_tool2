from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from app import create_app


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "mini_system"


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_api_health_and_run(client, tmp_path):
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    body = health.get_json()
    assert body["ok"] is True
    assert 1 in body["implemented_stages"]

    source = Path(__file__).parent / "fixtures" / "mini_system"
    isolated_source = tmp_path / "source"
    shutil.copytree(source, isolated_source)
    response = client.post(
        "/api/v1/runs",
        json={"stages": [1], "source_dir": str(isolated_source), "options": {"determinism_check": True}},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["stage1_running_confirmed"] is True
    assert payload["verification"]["verified"] is True
    assert payload["stages"][0]["stage"] == 1
    assert set(payload["recall"]) == {"checked_types", "mismatches"}
    assert payload["recall"]["mismatches"] == 0
    assert payload["manifest"]["source_identity"]["file_count"] == 6
    assert len(payload["manifest"]["source_identity"]["snapshot_id"]) == 64
    assert payload["evidence_pack_path"].endswith("stage1_evidence_pack.md")
    evidence = client.get(f"/api/v1/runs/{payload['run_id']}/stages/1/evidence-pack")
    assert evidence.status_code == 200
    assert evidence.content_type.startswith("text/markdown")


def test_stage2_not_implemented(client, tmp_path):
    source = tmp_path / "source"
    shutil.copytree(FIXTURE_DIR, source)
    response = client.post("/api/v1/stages/2/run", json={"source_dir": str(source)})
    assert response.status_code == 501
    body = response.get_json()
    assert body["error"]["code"] == "STAGE_NOT_IMPLEMENTED"


def test_unknown_run_returns_404(client):
    response = client.get("/api/v1/runs/nope")
    assert response.status_code == 404
    body = response.get_json()
    assert body["error"]["code"] == "RUN_NOT_FOUND"


def test_artifact_path_traversal_rejected(client, tmp_path):
    source = tmp_path / "source"
    shutil.copytree(FIXTURE_DIR, source)
    run_response = client.post("/api/v1/runs", json={"stages": [1], "source_dir": str(source)})
    run_id = run_response.get_json()["run_id"]
    response = client.get(f"/api/v1/runs/{run_id}/stages/1/artifacts/../../../../etc/passwd")
    assert response.status_code == 400
    body = response.get_json()
    assert body["error"]["code"] == "INVALID_ARTIFACT_NAME"
