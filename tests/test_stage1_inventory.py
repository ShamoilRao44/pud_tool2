from __future__ import annotations

import json
import hashlib
import re
import shutil
from pathlib import Path

import pytest

from app.core.registry import get_stage, list_stages
from app.core.runner import run_pipeline
from verification.recall import scan_source


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "mini_system"


def _copy_fixture(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    shutil.copytree(FIXTURE_DIR, source)
    return source


def _tree_hash(source: Path) -> str:
    entries = []
    for path in sorted((path for path in source.rglob("*") if path.is_file()), key=lambda path: path.relative_to(source).as_posix()):
        entries.append(f"{path.relative_to(source).as_posix()}:{hashlib.sha256(path.read_bytes()).hexdigest()}")
    return hashlib.sha256("\n".join(entries).encode()).hexdigest()


def test_independent_recall_tokenizes_fixed_and_multiline_code(tmp_path):
    (tmp_path / "sample").write_text(
        "000100 IDENTIFICATION DIVISION.\n"
        "000200* CALL 'COMMENTED'\n"
        "000300     EXEC CICS LINK\n"
        "000400       PROGRAM('TARGET')\n"
        "000500       END-EXEC.\n"
        "000600     DISPLAY 'CALL FAKE'.\n"
        "000700     COPY MEMBER.\n",
        encoding="ascii",
    )

    result = scan_source(tmp_path)

    assert result["reference_counts"] == {"CICS_LINK": 1, "COPY": 1}
    assert result["cics_verbs"] == {"LINK": 1}
    assert result["files"]["sample"]["references"] == [
        {"type": "CICS_LINK", "target": "@LIT", "line": 3},
        {"type": "COPY", "target": "MEMBER", "line": 7},
    ]


def test_stage1_fixture_classification_and_references(tmp_path):
    source = _copy_fixture(tmp_path)
    before = _tree_hash(source)
    payload = run_pipeline(
        source_dir=str(source),
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
    assert summary["references_total"] == sum(summary["references_by_type"].values())
    assert payload["stages"][0]["verification"]["checks_total"] == 20
    assert payload["stages"][0]["verification"]["recall"]["mismatches"] == 0
    assert summary["entry_point_candidates"] >= 1
    assert summary["gaps_open"] >= 1

    refs = payload["stages"][0]["artifacts_by_name"]["references"]
    assert refs["data"]["references"]
    assert all(len(ref["evidence"]["excerpt"]) <= 120 for ref in refs["data"]["references"])
    assert _tree_hash(source) == before


def test_stage1_verification_and_idempotence(tmp_path):
    source = _copy_fixture(tmp_path)
    run1 = run_pipeline(source_dir=str(source), stages=[1], options={"determinism_check": True})
    run2 = run_pipeline(source_dir=str(source), stages=[1], options={"determinism_check": True})

    assert run1["ok"] is True
    assert run2["ok"] is True
    assert run1["run_id"] != run2["run_id"]

    art1 = run1["stages"][0]["artifacts_by_name"]
    art2 = run2["stages"][0]["artifacts_by_name"]
    for name in art1:
        first = json.dumps(art1[name]["data"])
        second = json.dumps(art2[name]["data"])
        first = re.sub(r"Run: [^\\n]+", "Run: <run-id>", first)
        second = re.sub(r"Run: [^\\n]+", "Run: <run-id>", second)
        assert first == second

    verification = run1["stages"][0]["verification"]
    assert verification["checks_total"] == 20
    assert verification["failed"] == 0
    assert verification["verified"] is True
    assert len(run1["source_snapshot_id"]) == 64


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
