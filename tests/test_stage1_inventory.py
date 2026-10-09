from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.registry import get_stage, list_stages
from app.core.runner import run_pipeline


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "mini_system"


def test_stage1_fixture_classification_and_references():
    payload = run_pipeline(
        source_dir=str(FIXTURE_DIR),
        stages=[1],
        base_run_id=None,
        options={"determinism_check": True},
    )

    assert payload["ok"] is True
    assert payload["stages"][0]["stage"] == 1
    assert payload["stages"][0]["stage1_running_confirmed"] is True
    assert payload["stages"][0]["verification"]["verified"] is True

    summary = payload["stages"][0]["summary"]
    assert summary["files_found"] == 6
    assert summary["files_classified"] == 6
    assert summary["files_unclassified"] == 0
    assert summary["by_type"]["COBOL_FRAGMENT"] == 1
    assert summary["by_type"]["COBOL_PROGRAM"] == 3
    assert summary["by_type"]["COBOL_COPYBOOK"] == 1
    assert summary["by_type"]["HLASM"] == 1
    assert summary["references_total"] == 6
    assert summary["references_resolved"] == 4
    assert summary["references_unresolved"] == 1
    assert summary["references_external_system"] == 1
    assert summary["references_dynamic"] == 1
    assert summary["entry_point_candidates"] >= 1
    assert summary["gaps_open"] >= 1
    assert summary["anomalies"] >= 1

    refs = payload["stages"][0]["artifacts_by_name"]["references"]
    statuses = {r["status"] for r in refs["data"]["references"]}
    assert statuses == {"RESOLVED", "EXTERNAL_SYSTEM", "DYNAMIC", "UNRESOLVED"}

    missing = {g["name"] for g in payload["stages"][0]["artifacts_by_name"]["gaps_register"]["data"]["gaps"] if g["gap_type"] == "MISSING_ARTIFACT"}
    assert missing == {"CIPTMON"}

    found = payload["stages"][0]["artifacts_by_name"]["anomalies"]["data"]["findings"]
    assert any(f["type"] == "NON_CODE_TEXT" for f in found)
    assert any(f["type"] == "ELIDED_CODE_MARKER" for f in found)
    assert any(f["type"] == "TEXT_BEYOND_COL72" for f in found)
    assert all("CALL 'CIPTMON'" not in f["evidence"][0]["excerpt"] for f in found if f["type"] == "COMMENTED_OUT_CALL")

    assert not any(ref["target_name"] == "COMMENTED_CALL" for ref in refs["data"]["references"])


def test_stage1_verification_and_idempotence():
    run1 = run_pipeline(source_dir=str(FIXTURE_DIR), stages=[1], options={"determinism_check": True})
    run2 = run_pipeline(source_dir=str(FIXTURE_DIR), stages=[1], options={"determinism_check": True})

    assert run1["ok"] is True
    assert run2["ok"] is True
    assert run1["run_id"] != run2["run_id"]

    art1 = run1["stages"][0]["artifacts_by_name"]
    art2 = run2["stages"][0]["artifacts_by_name"]
    for name in art1:
        assert json.dumps(art1[name]["data"]) == json.dumps(art2[name]["data"])

    verification = run1["stages"][0]["verification"]
    assert verification["checks_total"] == 13
    assert verification["failed"] == 0
    assert verification["verified"] is True


def test_stage1_registry_and_dummy_stage_plugin():
    stages = list_stages()
    assert 1 in {s["number"] for s in stages}
    assert 5 in {s["number"] for s in stages}

    stage = get_stage(1)
    assert stage is not None
    assert stage.name == "inventory"


@pytest.mark.skipif(not pytest.importorskip("app"), reason="package not available")
def test_stage1_smoke_against_real_tree():
    import os

    source_dir = os.getenv("SOURCE_DIR")
    if not source_dir:
        pytest.skip("SOURCE_DIR not set")

    payload = run_pipeline(source_dir=source_dir, stages=[1], options={"determinism_check": False})
    assert payload["ok"] is True
    assert payload["stages"][0]["verification"]["verified"] is True
    assert payload["stages"][0]["summary"]["files_found"] >= 1
