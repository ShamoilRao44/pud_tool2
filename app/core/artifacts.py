from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import jsonschema


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class ArtifactStore:
    def __init__(self, root_dir: str | Path):
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def write_envelope(self, run_id: str, stage: int, artifact_name: str, data: Any, schema_name: str | None = None, source_snapshot_id: str | None = None, tool_version: str = "0.1.0") -> tuple[Path, dict[str, Any]]:
        artifact_dir = self.root_dir / f"stage{stage}"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": "1.0",
            "artifact": artifact_name,
            "stage": stage,
            "run_id": run_id,
            "source_snapshot_id": source_snapshot_id or "",
            "tool_version": tool_version,
            "generated_at": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "content_hash": hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest(),
            "data": data,
        }
        if schema_name:
            schema_path = Path(__file__).resolve().parents[1] / "schemas" / f"stage{stage}" / schema_name
            if schema_path.exists():
                with schema_path.open("r", encoding="utf-8") as fh:
                    schema = json.load(fh)
                jsonschema.validate(data, schema)
        path = artifact_dir / f"{artifact_name}.json"
        path.write_text(canonical_json(payload) + "\n", encoding="utf-8")
        return path, payload

    def read_envelope(self, path: Path) -> dict[str, Any]:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)


def write_latest_manifest(root_dir: Path, run_id: str) -> None:
    latest_path = root_dir / "latest.json"
    latest_path.write_text(json.dumps({"run_id": run_id}, sort_keys=True), encoding="utf-8")
