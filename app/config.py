from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values


@dataclass(frozen=True)
class AppConfig:
    source_dir: str | None
    output_dir: str
    main_program: str | None
    flask_host: str
    flask_port: int
    log_level: str
    allow_source_override: bool
    sequence_area_strict: bool
    max_file_bytes: int
    ignore_patterns: tuple[str, ...]
    known_external_prefixes: tuple[str, ...]
    known_external_names: tuple[str, ...]
    folder_hints: tuple[str, ...]


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def load_config(source_dir: str | None = None, env_file: str | None = None) -> AppConfig:
    root = Path(__file__).resolve().parent.parent
    env_path = Path(env_file) if env_file else root / ".env"
    values = dotenv_values(env_path)
    env_values = {**values, **os.environ}

    chosen_source_dir = source_dir if source_dir is not None else env_values.get("SOURCE_DIR")
    if not chosen_source_dir:
        raise ValueError("SOURCE_DIR is required and must point to the legacy source tree.")
    source_path = Path(chosen_source_dir).expanduser()
    if not source_path.is_dir():
        raise ValueError(f"SOURCE_DIR does not exist or is not a directory: {chosen_source_dir}")
    source_path = source_path.resolve()
    try:
        next(source_path.iterdir(), None)
        if not any(path.is_file() for path in source_path.rglob("*")):
            raise ValueError(f"SOURCE_DIR is empty: {source_path}")
    except OSError as exc:
        raise ValueError(f"SOURCE_DIR cannot be read: {source_path}: {exc}") from exc

    output_dir = env_values.get("OUTPUT_DIR", "./output")
    main_program = env_values.get("MAIN_PROGRAM")
    ignore_patterns = tuple(part.strip() for part in str(env_values.get("IGNORE_PATTERNS", "")).split(",") if part.strip())
    known_external_prefixes = tuple(part.strip() for part in str(env_values.get("KNOWN_EXTERNAL_PREFIXES", "")).split(",") if part.strip())
    known_external_names = tuple(part.strip() for part in str(env_values.get("KNOWN_EXTERNAL_NAMES", "")).split(",") if part.strip())
    folder_hints = tuple(part.strip() for part in str(env_values.get("FOLDER_HINTS", "")).split(",") if part.strip())

    return AppConfig(
        source_dir=str(source_path),
        output_dir=str(Path(output_dir)),
        main_program=main_program,
        flask_host=env_values.get("FLASK_HOST", "127.0.0.1"),
        flask_port=int(env_values.get("FLASK_PORT", "5000")),
        log_level=env_values.get("LOG_LEVEL", "INFO"),
        allow_source_override=_parse_bool(env_values.get("ALLOW_SOURCE_OVERRIDE"), False),
        sequence_area_strict=_parse_bool(env_values.get("SEQUENCE_AREA_STRICT"), True),
        max_file_bytes=int(env_values.get("MAX_FILE_BYTES", "20000000")),
        ignore_patterns=ignore_patterns,
        known_external_prefixes=known_external_prefixes,
        known_external_names=known_external_names,
        folder_hints=folder_hints,
    )
