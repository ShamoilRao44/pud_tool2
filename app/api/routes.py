from __future__ import annotations

import json
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

from app.config import load_config
from app.core.registry import get_stage, list_stages
from app.core.runner import run_pipeline
from app.api.errors import ApiError

api_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")


@api_bp.route("/health", methods=["GET"])
def health():
    try:
        cfg = current_app.config.get("APP_CONFIG")
        source_dir_exists = False
        if cfg and cfg.source_dir:
            source_dir_exists = Path(cfg.source_dir).exists()
    except Exception:
        source_dir_exists = False
    return jsonify({
        "ok": True,
        "tool_version": "0.1.0",
        "source_dir_exists": source_dir_exists,
        "implemented_stages": [1],
    })


@api_bp.route("/stages", methods=["GET"])
def stages():
    return jsonify({"ok": True, "stages": list_stages()})


@api_bp.route("/runs", methods=["POST"])
def create_run():
    payload = request.get_json(silent=True) or {}
    if payload is None:
        payload = {}
    stages = payload.get("stages", [1])
    source_dir = payload.get("source_dir")
    base_run_id = payload.get("base_run_id")
    options = payload.get("options") or {}
    if source_dir is None:
        cfg = current_app.config.get("APP_CONFIG")
        source_dir = cfg.source_dir if cfg else None
    try:
        result = run_pipeline(source_dir=source_dir, stages=stages, base_run_id=base_run_id, options=options)
    except ValueError as exc:
        raise ApiError("INVALID_SOURCE_DIR", str(exc), 400) from exc
    except RuntimeError as exc:
        if "not implemented" in str(exc):
            raise ApiError("STAGE_NOT_IMPLEMENTED", str(exc), 501) from exc
        raise ApiError("PIPELINE_ERROR", str(exc), 500) from exc
    if not result["ok"]:
        raise ApiError("PIPELINE_FAILED", "pipeline failed", 500)
    run_id = result["run_id"]
    manifest_path = Path("output") / run_id / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else result["manifest"]
    stage_response = result["stages"][0]
    response = {
        "ok": True,
        "run_id": run_id,
        "source_snapshot_id": result["source_snapshot_id"],
        "stages": [stage_response],
        "verification": stage_response["verification"],
        "stage1_running_confirmed": True,
        "manifest": manifest,
    }
    return jsonify(response)


@api_bp.route("/stages/<int:stage_number>/run", methods=["POST"])
def stage_run(stage_number: int):
    payload = request.get_json(silent=True) or {}
    if stage_number not in (1,):
        raise ApiError("STAGE_NOT_IMPLEMENTED", f"Stage {stage_number} is not implemented", 501)
    stages = [stage_number]
    result = run_pipeline(source_dir=payload.get("source_dir"), stages=stages, base_run_id=payload.get("base_run_id"), options=payload.get("options") or {})
    return jsonify(result)


@api_bp.route("/runs", methods=["GET"])
def list_runs():
    output_dir = Path("output")
    runs = []
    if output_dir.exists():
        for p in sorted(output_dir.iterdir(), reverse=True):
            if p.is_dir():
                manifest = p / "run_manifest.json"
                if manifest.exists():
                    runs.append({"run_id": p.name, "manifest": json.loads(manifest.read_text(encoding="utf-8"))})
    return jsonify({"ok": True, "runs": runs})


@api_bp.route("/runs/<run_id>", methods=["GET"])
def get_run(run_id: str):
    manifest_path = Path("output") / run_id / "run_manifest.json"
    if not manifest_path.exists():
        raise ApiError("RUN_NOT_FOUND", f"Run {run_id} not found", 404)
    return jsonify(json.loads(manifest_path.read_text(encoding="utf-8")))


@api_bp.route("/runs/<run_id>/stages/<int:stage_number>", methods=["GET"])
def get_stage_summary(run_id: str, stage_number: int):
    manifest_path = Path("output") / run_id / "run_manifest.json"
    if not manifest_path.exists():
        raise ApiError("RUN_NOT_FOUND", f"Run {run_id} not found", 404)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for stage in manifest["stages"]:
        if stage["stage"] == stage_number:
            return jsonify({"ok": True, "stage": stage})
    raise ApiError("STAGE_NOT_FOUND", f"Stage {stage_number} not found", 404)


@api_bp.route("/runs/<run_id>/stages/<int:stage_number>/artifacts/<path:artifact_name>", methods=["GET"])
def get_artifact(run_id: str, stage_number: int, artifact_name: str):
    artifact_name = artifact_name.replace("..", "")
    if artifact_name.startswith("/") or "/../" in artifact_name or ".." in artifact_name:
        raise ApiError("INVALID_ARTIFACT_NAME", "Artifact name must be a safe relative name", 400)
    manifest_path = Path("output") / run_id / "run_manifest.json"
    if not manifest_path.exists():
        raise ApiError("RUN_NOT_FOUND", f"Run {run_id} not found", 404)
    artifact_path = Path("output") / run_id / f"stage{stage_number}" / f"{artifact_name}.json"
    if not artifact_path.exists() or not artifact_path.is_file():
        raise ApiError("ARTIFACT_NOT_FOUND", "Artifact not found", 404)
    try:
        with artifact_path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception as exc:
        raise ApiError("INVALID_ARTIFACT", "Artifact could not be read", 500) from exc
    return jsonify({"ok": True, "artifact": payload})


@api_bp.route("/runs/<run_id>/stages/<int:stage_number>/report", methods=["GET"])
def get_report(run_id: str, stage_number: int):
    report_path = Path("output") / run_id / f"stage{stage_number}" / "stage1_summary.md"
    if not report_path.exists():
        raise ApiError("REPORT_NOT_FOUND", "Report not found", 404)
    return report_path.read_text(encoding="utf-8"), 200, {"Content-Type": "text/markdown; charset=utf-8"}


@api_bp.errorhandler(ApiError)
def handle_api_error(error: ApiError):
    return error.to_response()
