from __future__ import annotations

import random
import shutil
import string
from collections import Counter
from pathlib import Path

import pytest

from app.core.runner import run_pipeline
from tests.test_stage1_inventory import FIXTURE_DIR, _tree_hash


def _write(root: Path, relative: str, content: str | bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content) if isinstance(content, bytes) else path.write_text(content, encoding="utf-8")
    return path


def _run(root: Path):
    return run_pipeline(source_dir=str(root), stages=[1], options={"determinism_check": False})


def _stage(payload):
    return payload["stages"][0]


def _reference_counts(stage):
    return dict(Counter(ref["type"] for ref in stage["artifacts_by_name"]["references"]["data"]["references"]))


def test_free_format_extensions_jcl_proc_bms_and_sql(tmp_path, monkeypatch):
    source = tmp_path / "free"
    _write(source, "main.cbl", """identification division.
program-id. alpha.
procedure division.
exec cics link program('beta') end-exec.
exec cics send map('screen') mapset('panel') end-exec.
exec sql include SQLCA end-exec.
copy cpyone.
call 'missing-vendor'.
stop run.
""")
    _write(source, "beta.cbl", "identification division.\nprogram-id. beta.\nprocedure division.\n")
    _write(source, "cpyone.cpy", "01 DATA-ITEM PIC X.\n")
    _write(source, "job.jcl", "//JOB JOB (ACCT)\n//STEP EXEC PGM=ALPHA\n//NEXT EXEC PROCX\n")
    _write(source, "panel.bms", "MAPSET DFHMSD TYPE=MAP\n")
    _write(source, "schema.sql", "select 1 from sysibm.sysdummy1;\n")
    monkeypatch.setenv("MAIN_PROGRAM", "ALPHA")
    monkeypatch.setenv("KNOWN_EXTERNAL_NAMES", "SQLCA")
    monkeypatch.setenv("KNOWN_EXTERNAL_PREFIXES", "")

    stage = _stage(_run(source))

    assert stage["verification"]["verified"] is True
    assert _reference_counts(stage) == {"CICS_LINK": 1, "CICS_MAPSET": 1, "SQL_INCLUDE": 1, "COPY": 1, "CALL": 1, "JCL_EXEC_PGM": 1, "JCL_EXEC_PROC": 1}
    candidates = stage["artifacts_by_name"]["entry_points"]["data"]["candidates"]
    assert {(item["name"], item["kind"]) for item in candidates} == {("ALPHA", "E1"), ("ALPHA", "E4")}
    assert all(item["line"] == 2 for item in candidates)
    gaps = stage["artifacts_by_name"]["gaps_register"]["data"]["gaps"]
    assert Counter(gap["gap_type"] for gap in gaps) == Counter({"UNDEFINED_INTERNAL_TARGET": 1, "MISSING_ARTIFACT": 1, "UNSUPPORTED_LANGUAGE": 2})
    assert stage["verification"]["recall"]["mismatches"] == 0


def test_fixed_multiline_nested_copybooks_and_literal_comment_exclusion(tmp_path, monkeypatch):
    source = tmp_path / "fixed"
    _write(source, "odd/folder/entry", """000100 IDENTIFICATION DIVISION.
000200 PROGRAM-ID. ROOTUNIT.
000300 PROCEDURE DIVISION.
000400     EXEC CICS LINK
000500       PROGRAM('TARGETUNIT')
000550*    CALL 'COMMENTED'.
000600     END-EXEC.
000700     EXEC SQL INCLUDE SQLCA END-EXEC.
000800     COPY OUTERCPY.
000900*    CALL 'COMMENTED'.
001000     DISPLAY 'CALL FAKE EXEC CICS LINK PROGRAM(FAKE)'.
""")
    _write(source, "other/target", "000100 IDENTIFICATION DIVISION.\n000200 PROGRAM-ID. TARGETUNIT.\n000300 PROCEDURE DIVISION.\n")
    _write(source, "nested/outercpy", "000100 COPY INNERCPY.\n000200 01 OUTER-ITEM PIC X.\n")
    _write(source, "deeper/innercpy", "000100 01 INNER-ITEM PIC X.\n")
    with (source / "odd/folder/entry").open("a", encoding="utf-8") as stream:
        stream.write("001100     COPY INNER-ITEM.\n")
    monkeypatch.setenv("KNOWN_EXTERNAL_NAMES", "SQLCA")
    monkeypatch.setenv("KNOWN_EXTERNAL_PREFIXES", "")
    before = _tree_hash(source)

    stage = _stage(_run(source))

    assert stage["verification"]["verified"] is True
    assert _reference_counts(stage) == {"CICS_LINK": 1, "SQL_INCLUDE": 1, "COPY": 3}
    assert not any(ref["target_name"] in {"COMMENTED", "FAKE"} for ref in stage["artifacts_by_name"]["references"]["data"]["references"])
    copy_evidence = [ref["evidence"] for ref in stage["artifacts_by_name"]["references"]["data"]["references"] if ref["type"] == "CICS_LINK"]
    assert copy_evidence[0]["seq"] == "000400"
    assert copy_evidence[0]["end_line"] == 7
    definitions = stage["artifacts_by_name"]["name_index"]["data"]["defined_names"]
    assert "OUTER-ITEM" in definitions
    assert "INNER-ITEM" in definitions
    gaps = stage["artifacts_by_name"]["gaps_register"]["data"]["gaps"]
    assert [(gap["gap_type"], gap["name"]) for gap in gaps] == [("NO_ORCHESTRATION_INPUT", "orchestration-input")]
    assert _tree_hash(source) == before


def _identifier(rng: random.Random, marker: str) -> str:
    suffix = "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(rng.randint(3, 6)))
    return f"{marker}{rng.choice(('O0', 'I1'))}{suffix}"


@pytest.mark.parametrize("seed", [7, 19, 41, 73, 101])
def test_randomized_names_match_generation_plan(tmp_path, monkeypatch, seed):
    rng = random.Random(seed)
    program = _identifier(rng, "P")
    target_program = _identifier(rng, "Q")
    copy_name = _identifier(rng, "C")
    nested_copy = _identifier(rng, "N")
    missing_name = _identifier(rng, "M")
    data_name = _identifier(rng, "D")
    source = tmp_path / f"seed-{seed}"
    _write(source, f"{program.lower()}.cbl", f"identification division.\nprogram-id. {program}.\nprocedure division.\nexec cics link program('{target_program}') end-exec.\ncopy {copy_name}.\ncall '{missing_name}'.\n")
    _write(source, f"{target_program.lower()}.cbl", f"identification division.\nprogram-id. {target_program}.\nprocedure division.\n")
    _write(source, f"{copy_name.lower()}.cpy", f"copy {nested_copy}.\n01 {data_name} pic x.\n")
    _write(source, f"{nested_copy.lower()}.cpy", f"01 {_identifier(rng, 'Z')} pic x.\n")
    monkeypatch.setenv("MAIN_PROGRAM", program)
    monkeypatch.setenv("KNOWN_EXTERNAL_NAMES", "")
    monkeypatch.setenv("KNOWN_EXTERNAL_PREFIXES", "")

    stage = _stage(_run(source))

    plan = {"CICS_LINK": 1, "COPY": 2, "CALL": 1}
    assert _reference_counts(stage) == plan
    assert stage["verification"]["verified"] is True
    assert stage["verification"]["checks_total"] == 20
    assert all(check["status"] == "PASS" for check in stage["verification"]["checks"])
    candidates = stage["artifacts_by_name"]["entry_points"]["data"]["candidates"]
    assert any(candidate["kind"] == "E1" and candidate["name"] == program for candidate in candidates)
    gaps = stage["artifacts_by_name"]["gaps_register"]["data"]["gaps"]
    assert any(gap["gap_type"] == "UNDEFINED_INTERNAL_TARGET" and gap["name"] == missing_name for gap in gaps)


def test_mutation_dropping_extracted_reference_fails_v14(tmp_path, monkeypatch):
    source = tmp_path / "mutated"
    shutil.copytree(FIXTURE_DIR, source)
    before = _tree_hash(source)
    good = _stage(_run(source))
    assert good["verification"]["checks"][13]["status"] == "PASS"

    import app.stages.stage1_inventory.engine as engine

    original = engine.scan_file
    did_drop = False

    def drop_one_reference(path, root, folder_hints=()):
        nonlocal did_drop
        scanned = original(path, root, folder_hints)
        if not did_drop and scanned["references"]:
            scanned["references"].pop()
            did_drop = True
        return scanned

    with monkeypatch.context() as patch:
        patch.setattr(engine, "scan_file", drop_one_reference)
        mutated = _stage(_run(source))
    assert did_drop
    assert mutated["verification"]["checks"][13]["status"] == "FAIL"
    assert mutated["verification"]["recall"]["mismatches"] > 0
    assert mutated["verification"]["verified"] is False
    assert _tree_hash(source) == before


def test_config_free_run_uses_roots_and_keeps_unknown_targets(tmp_path, monkeypatch):
    source = tmp_path / "config-free"
    _write(source, "root-a.cbl", "identification division.\nprogram-id. ROOTA.\nprocedure division.\ncall 'VENDORX'.\n")
    _write(source, "root-b.cbl", "identification division.\nprogram-id. ROOTB.\nprocedure division.\n")
    monkeypatch.delenv("MAIN_PROGRAM", raising=False)
    monkeypatch.setenv("KNOWN_EXTERNAL_NAMES", "")
    monkeypatch.setenv("KNOWN_EXTERNAL_PREFIXES", "")

    stage = _stage(_run(source))

    assert stage["verification"]["verified"] is True
    refs = stage["artifacts_by_name"]["references"]["data"]["references"]
    assert any(ref["target_name"] == "VENDORX" and ref["status"] == "UNRESOLVED" for ref in refs)
    assert sum(candidate["kind"] == "E2" for candidate in stage["artifacts_by_name"]["entry_points"]["data"]["candidates"]) == 2


def test_redact_excerpts_replaces_literals_in_pack(tmp_path):
    source = tmp_path / "redacted"
    _write(source, "entry.cbl", "program-id. ROOT.\ncall 'PRIVATE-TARGET'.\n")

    stage = _stage(run_pipeline(source_dir=str(source), stages=[1], options={"redact_excerpts": True}))
    pack = stage["artifacts_by_name"]["stage1_evidence_pack"]["data"]

    sample = pack.split("## 10. Sample of evidence", 1)[1]
    assert "call <literal>" in sample
    assert "call 'PRIVATE-TARGET'" not in sample


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("empty.cbl", b""),
        ("binary.bin", b"\x00\xff\x80\x00"),
        ("comments.cbl", b"*> only a comment\n"),
        ("long.cbl", ("X" * 12000 + "\n").encode()),
        ("tabs.cbl", b"\tEXEC CICS LINK PROGRAM('TARGET') END-EXEC.\n"),
        ("mixed.cbl", b"identification division.\r\nprogram-id. MIXED.\n"),
        ("legacy.cbl", "*> caf\u00e9\r\n".encode("cp1252")),
        ("jcl-comments.jcl", b"//*STEP EXEC PGM=SHOULDNOTCOUNT\n"),
        ("narrative.txt", b"This is an opening narrative sentence before code.\n"),
    ],
)
def test_robust_inputs_are_classified_and_recalled(tmp_path, name, content):
    source = tmp_path / name.replace(".", "-")
    _write(source, name, content)

    stage = _stage(_run(source))

    assert stage["summary"]["files_found"] == 1
    assert stage["verification"]["recall"]["mismatches"] == 0
    assert stage["verification"]["checks"][13]["status"] == "PASS"
    assert stage["artifacts_by_name"]["file_inventory"]["data"]["files"][0]["classification"]["type"]
    if name == "narrative.txt":
        assert any(item["type"] == "NON_CODE_TEXT" for item in stage["artifacts_by_name"]["anomalies"]["data"]["findings"])


def test_empty_source_and_output_inside_source_fail_clearly(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="empty"):
        _run(empty)

    source = tmp_path / "source"
    _write(source, "unit.cbl", "program-id. UNIT.\n")
    monkeypatch.setenv("OUTPUT_DIR", str(source / "generated"))
    with pytest.raises(ValueError, match="outside SOURCE_DIR"):
        _run(source)

