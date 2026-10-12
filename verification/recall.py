from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any


def _tokens_from_line(line: str, fixed: bool) -> tuple[list[str], bool]:
    continuation = False
    stripped = line.lstrip()
    if stripped.startswith(("//*", "--", "*>")) or (not line[:6].isdigit() and stripped.startswith("*")):
        return [], False
    if fixed:
        if len(line) >= 7 and line[:6].isdigit():
            if line[6:7] in {"*", "/", "D", "d"}:
                return [], False
            continuation = line[6:7] == "-"
            line = line[7:72]
        elif len(line) >= 7 and line[6:7] in {"*", "/", "D", "d"}:
            return [], False

    tokens: list[str] = []
    current: list[str] = []
    quote = ""
    literal_value: list[str] = []
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == quote:
                if index + 1 < len(line) and line[index + 1] == quote:
                    literal_value.append(char)
                    index += 1
                else:
                    tokens.append("@LIT")
                    literal_value = []
                    quote = ""
            else:
                literal_value.append(char)
        elif char in {"'", '"'}:
            if current:
                tokens.append("".join(current).upper())
                current.clear()
            quote = char
            literal_value = []
        elif line[index:index + 2] == "*>":
            break
        elif line[index:index + 2] == "--":
            break
        elif char.isalnum() or char in {"_", "-", "$", "#", "@"}:
            current.append(char)
        elif char == ".":
            if current:
                tokens.append("".join(current).upper())
                current.clear()
            tokens.append(".")
        else:
            if current:
                tokens.append("".join(current).upper())
                current.clear()
        index += 1
    if current:
        tokens.append("".join(current).upper())
    return tokens, continuation


def scan_source(source_dir: str | Path, relative_paths: list[str] | None = None) -> dict[str, Any]:
    """Count source references without using the Stage 1 extractor's parsing code."""
    root = Path(source_dir).resolve()
    paths = (
        [root / item for item in relative_paths]
        if relative_paths is not None
        else sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.relative_to(root).as_posix())
    )
    per_file: dict[str, Any] = {}
    totals: Counter[str] = Counter()
    cics_totals: Counter[str] = Counter()
    sql_totals: Counter[str] = Counter()
    for path in paths:
        relative = path.relative_to(root).as_posix()
        raw_lines = path.read_bytes().decode("cp1252", errors="replace").splitlines()
        fixed = any(len(line) >= 7 and line[:6].isdigit() for line in raw_lines[:8])
        physical_tokens: list[tuple[list[str], int, bool]] = []
        for line_number, line in enumerate(raw_lines, 1):
            line_tokens, continuation = _tokens_from_line(line, fixed)
            if line_tokens:
                physical_tokens.append((line_tokens, line_number, continuation))

        statements: list[list[tuple[str, int]]] = []
        pending: list[tuple[str, int]] = []
        pending_kind = ""
        for line_tokens, line_number, continuation in physical_tokens:
            words = [token.upper() for token in line_tokens]
            starts_exec = len(words) > 1 and words[0] == "EXEC" and words[1] in {"CICS", "SQL"}
            starts_copy = words[0] == "COPY"
            starts_new = words[0] in {"CALL", "COPY", "EXEC", "DISPLAY", "MOVE", "PERFORM", "IF", "EVALUATE", "GO", "STOP", "GOBACK"}
            if pending and starts_new and not continuation and (pending_kind != "COPY" or not starts_copy):
                statements.append(pending)
                pending = []
                pending_kind = ""
            if not pending:
                pending_kind = "EXEC" if starts_exec else "COPY" if starts_copy else ""
            pending.extend((token, line_number) for token in line_tokens)
            words = [token for token, _ in pending]
            if pending_kind == "EXEC" and "END-EXEC" in words:
                statements.append(pending)
                pending = []
                pending_kind = ""
            elif pending_kind == "COPY" and "." in words:
                statements.append(pending)
                pending = []
                pending_kind = ""
            elif not pending_kind and not continuation:
                statements.append(pending)
                pending = []
        if pending:
            statements.append(pending)

        references: list[dict[str, Any]] = []
        cics: Counter[str] = Counter()
        sql: Counter[str] = Counter()
        keyword_counts: Counter[str] = Counter()
        for statement in statements:
            index = 0
            while index < len(statement):
                word, line_number = statement[index]
                next_word = statement[index + 1][0] if index + 1 < len(statement) else ""
                third_word = statement[index + 2][0] if index + 2 < len(statement) else ""
                ref_type = ""
                target = ""
                if word == "EXEC" and next_word == "CICS" and third_word:
                    verb = third_word
                    cics[verb] += 1
                    if verb in {"LINK", "XCTL", "LOAD"}:
                        ref_type = f"CICS_{verb}"
                        for target_index in range(index + 3, min(index + 12, len(statement))):
                            candidate = statement[target_index][0]
                            if candidate in {"PROGRAM", "PROGRAMID"} and target_index + 1 < len(statement):
                                target = statement[target_index + 1][0].removeprefix("@LIT:")
                                break
                    elif verb in {"SEND", "RECEIVE"}:
                        mapset_index = next((pos for pos in range(index + 3, len(statement)) if statement[pos][0] == "MAPSET"), None)
                        map_index = next((pos for pos in range(index + 3, len(statement)) if statement[pos][0] == "MAP"), None)
                        if mapset_index is not None or map_index is not None:
                            ref_type = "CICS_MAPSET"
                            target_index = mapset_index if mapset_index is not None else map_index
                            if target_index is not None and target_index + 1 < len(statement):
                                target = statement[target_index + 1][0].removeprefix("@LIT:")
                    elif verb in {"START", "RETURN"}:
                        if "TRANSID" in [token for token, _ in statement[index + 3:]]:
                            ref_type = f"CICS_{verb}"
                            transid_index = next((pos for pos in range(index + 3, len(statement)) if statement[pos][0] == "TRANSID"), None)
                            if transid_index is not None and transid_index + 1 < len(statement):
                                target = statement[transid_index + 1][0].removeprefix("@LIT:")
                elif word == "EXEC" and next_word == "SQL" and third_word:
                    sql[third_word] += 1
                    if third_word == "INCLUDE" and index + 3 < len(statement):
                        ref_type = "SQL_INCLUDE"
                        target = statement[index + 3][0].removeprefix("@LIT:")
                elif word == "COPY" and next_word:
                    ref_type = "COPY"
                    target = next_word.removeprefix("@LIT:")
                elif word == "CALL" and next_word:
                    ref_type = "CALL"
                    target = next_word.removeprefix("@LIT:")
                elif word == "EXEC" and next_word == "PGM" and third_word:
                    ref_type = "JCL_EXEC_PGM"
                    target = third_word
                elif word == "EXEC" and next_word and next_word not in {"CICS", "SQL", "PGM"}:
                    ref_type = "JCL_EXEC_PROC"
                    target = next_word

                if word in {"COPY", "CALL", "PERFORM", "GO", "EVALUATE", "IF"}:
                    keyword = "GO TO" if word == "GO" and next_word == "TO" else word
                    keyword_counts[keyword] += 1
                if ref_type:
                    references.append({"type": ref_type, "target": target, "line": line_number})
                index += 1

        for ref in references:
            totals[ref["type"]] += 1
        cics_totals.update(cics)
        sql_totals.update(sql)
        per_file[relative] = {
            "references": references,
            "reference_counts": dict(Counter(item["type"] for item in references)),
            "cics_verbs": dict(cics),
            "sql_verbs": dict(sql),
            "keyword_counts": dict(keyword_counts),
        }
    return {
        "files": per_file,
        "reference_counts": dict(totals),
        "cics_verbs": dict(cics_totals),
        "sql_verbs": dict(sql_totals),
    }