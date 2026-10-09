from __future__ import annotations

from typing import Callable, Type

_REGISTRY: dict[int, type] = {}


def register_stage(number: int):
    def decorator(cls: type):
        _REGISTRY[number] = cls
        return cls

    return decorator


def get_stage(number: int):
    return _REGISTRY.get(number)


def list_stages() -> list[dict]:
    all_numbers = set(range(1, 6))
    all_numbers |= set(_REGISTRY)
    stages = []
    for n in sorted(all_numbers):
        stage_cls = _REGISTRY.get(n)
        if stage_cls is None:
            stages.append({"number": n, "name": f"stage{n}", "implemented": False, "requires": ()})
        else:
            inst = stage_cls()
            stages.append({"number": n, "name": getattr(inst, "name", f"stage{n}"), "implemented": True, "requires": getattr(inst, "requires", ())})
    return stages
