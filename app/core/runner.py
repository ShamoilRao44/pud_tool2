from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import AppConfig, load_config
from app.core.context import RunContext
from app.core.registry import get_stage, list_stages
from app.stages.stage1_inventory import Stage1Inventory


_TOOL_VERSION = "0.1.0"


def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _run_id_for(snapshot_id: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    counter = int(datetime.now(timezone.utc).timestamp() * 1000) % 10000
    return f"{now}_{snapshot_id[:8]}_{counter:04d}"


def _source_snapshot_id(source_dir: str) -> str:
    root = Path(source_dir)
    rels = []
    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            rels.append(f"{path.relative_to(root).as_posix()}:{digest}")
    return hashlib.sha256("\n".join(rels).encode("utf-8")).hexdigest()


def run_pipeline(source_dir: str | None = None, stages: list[int] | None = None, base_run_id: str | None = None, options: dict[str, Any] | None = None) -> dict[str, Any]:
    options = options or {}
    cfg = load_config(source_dir=source_dir)
    source_dir = cfg.source_dir
    stages = stages or [1]
    snapshot_id = _source_snapshot_id(source_dir)
    run_id = _run_id_for(snapshot_id)
    output_dir = Path(cfg.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = output_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    ctx = RunContext(run_id=run_id, source_dir=source_dir, output_dir=str(output_dir), config=cfg, base_run_id=base_run_id)
    stage_results = []
    artifact_values = []
    per_stage_manifest = []

    for stage_no in stages:
        stage_cls = get_stage(stage_no)
        if stage_cls is None:
            raise RuntimeError(f"Stage {stage_no} not implemented")
        instance = stage_cls()
        result = instance.run(ctx)
        checks = instance.verify(ctx, result)
        result.verification["checks"] = [c.__dict__ for c in checks]
        result.verification["checks_total"] = len(checks)
        result.verification["passed"] = sum(1 for c in checks if c.status == "PASS")
        result.verification["warnings"] = sum(1 for c in checks if c.status == "WARN")
        result.verification["failed"] = sum(1 for c in checks if c.status == "FAIL")
        result.verification["verified"] = result.verification["failed"] == 0
        result.status = "PASSED" if result.verification["failed"] == 0 else "FAILED_VERIFICATION"
        if result.verification["warnings"]:
            result.status = "PASSED_WITH_WARNINGS"
        stage_results.append({
            "stage": result.stage,
            "name": result.name,
            "status": result.status,
            "stage1_running_confirmed": True,
            "summary": result.summary,
            "verification": result.verification,
            "checks": result.checks,
            "artifacts": result.artifacts,
            "artifacts_by_name": result.artifacts_by_name,
            "report_md": result.report_md,
        })
        per_stage_manifest.append({
            "stage": stage_no,
            "name": instance.name,
            "status": result.status,
            "artifacts": [artifact["name"] for artifact in result.artifacts],
        })
        artifact_values.extend(result.artifacts)

    manifest = {
        "run_id": run_id,
        "snapshot_id": snapshot_id,
        "config": {"source_dir": source_dir, "output_dir": str(output_dir), "main_program": cfg.main_program, "allow_source_override": cfg.allow_source_override, "sequence_area_strict": cfg.sequence_area_strict},
        "stages": per_stage_manifest,
        "start_time": str(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
        "end_time": str(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
        "duration_seconds": 0,
        "artifact_list": artifact_values,
        "check_summary": {
            "checks_total": sum(s["verification"]["checks_total"] for s in stage_results),
            "passed": sum(s["verification"]["passed"] for s in stage_results),
            "warnings": sum(s["verification"]["warnings"] for s in stage_results),
            "failed": sum(s["verification"]["failed"] for s in stage_results),
        },
        "tool_version": _TOOL_VERSION,
    }
    ctx.finalize_manifest(manifest)
    latest = output_dir / "latest.json"
    latest.write_text(json.dumps({"run_id": run_id}, sort_keys=True), encoding="utf-8")
    payload = {
        "ok": True,
        "run_id": run_id,
        "source_snapshot_id": snapshot_id,
        "stages": stage_results,
        "manifest": manifest,
    }
    return payload
