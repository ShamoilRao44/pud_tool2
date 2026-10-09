from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Evidence:
    file: str
    line: int | None = None
    seq: str | None = None
    excerpt: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "seq": self.seq,
            "excerpt": self.excerpt,
        }
