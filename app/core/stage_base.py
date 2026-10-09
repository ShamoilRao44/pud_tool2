from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CheckResult:
    id: str
    name: str
    status: str
    severity: str
    detail: str
    evidence_count: int = 0


@dataclass
class StageResult:
    stage: int
    name: str
    status: str
    summary: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)
    checks: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    report_md: str | None = None
    artifacts_by_name: dict[str, Any] = field(default_factory=dict)


class Stage(ABC):
    number: int = 0
    name: str = ""
    requires: tuple[int, ...] = ()

    @abstractmethod
    def run(self, ctx: Any) -> StageResult:
        raise NotImplementedError

    @abstractmethod
    def verify(self, ctx: Any, result: StageResult) -> list[CheckResult]:
        raise NotImplementedError
