from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import AppConfig
from app.core.artifacts import ArtifactStore


class RunContext:
    def __init__(self, run_id: str, source_dir: str, output_dir: str, config: AppConfig, base_run_id: str | None = None, source_snapshot_id: str = "", options: dict[str, Any] | None = None):
        self.run_id = run_id
        self.source_dir = source_dir
        self.output_dir = Path(output_dir)
        self.config = config
        self.base_run_id = base_run_id
        self.source_snapshot_id = source_snapshot_id
        self.options = options or {}
        self.run_dir = self.output_dir / run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.artifact_store = ArtifactStore(self.run_dir)
        self._artifact_map: dict[tuple[int, str], str] = {}

    def stage_dir(self, stage: int) -> Path:
        stage_dir = self.run_dir / f"stage{stage}"
        stage_dir.mkdir(parents=True, exist_ok=True)
        return stage_dir

    def write_artifact(self, stage: int, name: str, data: Any, schema: str | None = None) -> dict[str, Any]:
        path, payload = self.artifact_store.write_envelope(
            run_id=self.run_id,
            stage=stage,
            artifact_name=name,
            data=data,
            schema_name=schema,
            source_snapshot_id=self.source_snapshot_id,
            tool_version="0.2.0",
        )
        self._artifact_map[(stage, name)] = str(path)
        return payload

    def load_artifact(self, stage: int, name: str) -> dict[str, Any]:
        path = self.stage_dir(stage) / f"{name}.json"
        return self.artifact_store.read_envelope(path)

    def finalize_manifest(self, manifest: dict[str, Any]) -> None:
        with (self.run_dir / "run_manifest.json").open("w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
            fh.write("\n")
        with (self.output_dir / "latest.json").open("w", encoding="utf-8") as fh:
            json.dump({"run_id": self.run_id}, fh, sort_keys=True)
            fh.write("\n")
