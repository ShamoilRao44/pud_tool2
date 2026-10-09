from __future__ import annotations

from app.core.registry import get_stage, register_stage, list_stages


def test_framework_registers_dummy_stage():
    @register_stage(99)
    class DummyStage:
        number = 99
        name = "dummy"

        def __init__(self):
            self.requires = ()

        def run(self, ctx):
            return {"ok": True}

        def verify(self, ctx, result):
            return []

    assert get_stage(99) is not None
    stages = list_stages()
    assert any(s["number"] == 99 for s in stages)
