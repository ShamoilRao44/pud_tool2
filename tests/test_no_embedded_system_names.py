from __future__ import annotations

import ast
from pathlib import Path


def test_no_embedded_system_names():
    root = Path(__file__).resolve().parents[1]
    forbidden = {
        line.strip().casefold()
        for line in (root / "tests" / "forbidden_tokens.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    for path in (root / "app").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        literals = [node.value.casefold() for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        assert not any(token in literal for token in forbidden for literal in literals), f"{path} contains a forbidden literal"
