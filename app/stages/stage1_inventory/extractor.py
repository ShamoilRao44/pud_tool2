from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Any


_LITERAL_RE = re.compile(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"")
_WORD_RE = r"[A-Z0-9_$#@-]+"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_source(path: Path) -> tuple[str, str, bool]:
    raw = path.read_bytes()
    bom = raw.startswith(b"\xef\xbb\xbf")
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(encoding), encoding, False
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), "utf-8", True


def _source_lines(text: str) -> tuple[list[dict[str, Any]], str, str]:
    raw_lines = text.splitlines()
    line_ending = "MIXED" if "\r\n" in text and "\n" in text.replace("\r\n", "") else "CRLF" if "\r\n" in text else "LF" if "\n" in text else "NONE"
    fixed_count = sum(1 for line in raw_lines if len(line) >= 7 and line[:6].isdigit())
    source_format = "FIXED" if fixed_count and fixed_count >= max(1, len(raw_lines) // 3) else "FREE"
    output: list[dict[str, Any]] = []
    for line_number, raw in enumerate(raw_lines, 1):
        line = raw
        seq = None
        indicator = ""
        stripped = raw.lstrip()
        if stripped.startswith(("//*", "--", "*>")) or (not raw[:6].isdigit() and stripped.startswith("*")):
            output.append({"line": line_number, "raw": raw, "code": "", "seq": None, "kind": "comment", "continuation": False})
            continue
        if source_format == "FIXED" and len(raw) >= 7 and raw[:6].isdigit():
            seq = raw[:6]
            indicator = raw[6]
            if indicator in {"*", "/", "D", "d"}:
                output.append({"line": line_number, "raw": raw, "code": "", "seq": seq, "kind": "comment", "continuation": False})
                continue
            line = raw[7:72]
        elif source_format == "FIXED" and len(raw) >= 7 and raw[6] in {"*", "/"}:
            output.append({"line": line_number, "raw": raw, "code": "", "seq": None, "kind": "comment", "continuation": False})
            continue

        cleaned = _remove_inline_comment(line)
        if not cleaned.strip():
            kind = "comment" if raw.lstrip().startswith(("*> ", "// *", "#")) else "blank"
        elif raw.lstrip().startswith("//") and source_format != "FIXED":
            kind = "code" if "EXEC" in raw.upper() else "comment"
        elif _looks_like_narrative(cleaned):
            kind = "non_code"
        else:
            kind = "code"
        output.append({
            "line": line_number,
            "raw": raw,
            "code": cleaned,
            "seq": seq,
            "kind": kind,
            "continuation": indicator == "-",
        })
    return output, source_format, line_ending


def _remove_inline_comment(line: str) -> str:
    quote = ""
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == quote:
                if index + 1 < len(line) and line[index + 1] == quote:
                    index += 1
                else:
                    quote = ""
        elif char in {"'", '"'}:
            quote = char
        elif line[index:index + 2] == "*>":
            return line[:index]
        elif line[index:index + 2] == "--":
            return line[:index]
        index += 1
    return line


def _looks_like_narrative(line: str) -> bool:
    words = re.findall(r"[A-Za-z]+", line)
    return len(words) >= 5 and not re.search(r"\b(DIVISION|SECTION|PROGRAM-ID|EXEC|COPY|CALL|MOVE|DISPLAY|01|05)\b", line, re.I)


def _classify(path: Path, source_root: Path, lines: list[dict[str, Any]], folder_hints: tuple[str, ...]) -> str:
    suffix = path.suffix.lower()
    code = "\n".join(row["code"] for row in lines if row["kind"] == "code")
    upper = code.upper()
    if suffix in {".jcl", ".job", ".proc"} or re.search(r"(?m)^\s*//[^\n]*\bEXEC\b", code, re.I):
        return "JCL"
    if suffix == ".bms" or "DFHMSD" in upper:
        return "BMS"
    if suffix in {".asm", ".hlasm", ".s"} or re.search(r"\bCSECT\b", upper):
        return "HLASM"
    if suffix in {".cpy", ".copy"}:
        return "COBOL_COPYBOOK"
    if suffix in {".cbl", ".cob", ".cobol"}:
        return "COBOL_PROGRAM" if "PROGRAM-ID" in upper else "COBOL_FRAGMENT"
    if "PROGRAM-ID" in upper:
        return "COBOL_PROGRAM"
    if re.search(r"(?m)^\s*01\s+[A-Z0-9_-]+", upper):
        return "COBOL_COPYBOOK"
    if re.search(r"\b(EXEC\s+(?:CICS|SQL)|COPY\s+|CALL\s+|DIVISION\.)", upper):
        return "COBOL_FRAGMENT"
    if suffix == ".sql":
        return "SQL"
    if suffix in {".txt", ".md"}:
        return "TEXT"
    hint_names = {part.lower() for part in folder_hints}
    if any(part.lower() in hint_names for part in path.relative_to(source_root).parts[:-1]):
        return "COBOL_FRAGMENT"
    return "UNKNOWN"


def _logical_statements(lines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []
    pending: list[str] = []
    start_line = 0
    pending_end_line = 0
    pending_exec = False
    pending_copy = False
    for row in lines:
        if row["kind"] != "code":
            continue
        code = row["code"].strip()
        if not code:
            continue
        upper = code.upper()
        starts_exec = bool(re.search(r"\bEXEC\s+(?:CICS|SQL)\b", upper))
        starts_copy = bool(re.search(r"\bCOPY\s+", upper))
        starts_new_statement = bool(re.match(r"(?:EXEC|CALL|COPY|DISPLAY|MOVE|PERFORM|IF|EVALUATE|GO|STOP|GOBACK)\b", upper))
        if pending and starts_new_statement and not row["continuation"] and (pending_exec or pending_copy):
            statements.append({"text": "\n".join(pending), "line": start_line, "end_line": pending_end_line})
            pending = []
            pending_end_line = 0
            pending_exec = False
            pending_copy = False
        if not pending or starts_exec or starts_copy or row["continuation"]:
            if pending and not pending_exec and not pending_copy and not row["continuation"]:
                statements.append({"text": "\n".join(pending), "line": start_line, "end_line": pending_end_line})
                pending = []
                pending_end_line = 0
            if not pending:
                start_line = row["line"]
        pending.append(code)
        pending_end_line = row["line"]
        joined = "\n".join(pending)
        if pending_exec:
            pending_exec = "END-EXEC" not in joined.upper()
        elif starts_exec and "END-EXEC" not in upper:
            pending_exec = True
        if pending_copy:
            pending_copy = not bool(re.search(r"\.\s*$", joined))
        elif starts_copy and not re.search(r"\.\s*$", code):
            pending_copy = True
        if not pending_exec and not pending_copy:
            statements.append({"text": joined, "line": start_line, "end_line": pending_end_line})
            pending = []
            pending_end_line = 0
    if pending:
        statements.append({"text": "\n".join(pending), "line": start_line, "end_line": pending_end_line})
    return statements


def _mask_literals(text: str) -> tuple[str, dict[str, str]]:
    values: dict[str, str] = {}

    def replace(match: re.Match[str]) -> str:
        token = f"__STR{len(values)}__"
        values[token] = match.group(0)[1:-1].replace("''", "'").replace('""', '"')
        return token

    return _LITERAL_RE.sub(replace, text), values


def _resolve_literal(value: str, literals: dict[str, str]) -> tuple[str, bool]:
    if value in literals:
        return literals[value], False
    return value, True


def _statement_references(statement: dict[str, Any], relpath: str, seq_by_line: dict[int, str | None], is_jcl: bool) -> list[dict[str, Any]]:
    text = statement["text"]
    masked, literals = _mask_literals(text)
    refs: list[dict[str, Any]] = []

    def add(ref_type: str, target_expr: str, match: re.Match[str], attributes: dict[str, Any] | None = None) -> None:
        target, dynamic = _resolve_literal(target_expr, literals)
        refs.append({
            "type": ref_type,
            "target_name": target.strip(),
            "is_dynamic": dynamic,
            "attributes": attributes or {},
            "line": statement["line"],
            "end_line": statement.get("end_line", statement["line"]),
            "seq": seq_by_line.get(statement["line"]),
            "excerpt": re.sub(r"\s+", " ", text).strip()[:120],
        })

    exec_spans: list[tuple[int, int]] = []
    exec_pattern = re.compile(r"\bEXEC\s+CICS\s+(LINK|XCTL|LOAD|SEND|RECEIVE|START|RETURN)\b(.*?)(?:\bEND-EXEC\b|$)", re.I | re.S)
    for match in exec_pattern.finditer(masked):
        verb = match.group(1).upper()
        body = match.group(2)
        exec_spans.append(match.span())
        if verb in {"LINK", "XCTL", "LOAD"}:
            program = re.search(rf"\bPROGRAM\s*\(\s*({_WORD_RE})\s*\)", body, re.I)
            if program:
                add(f"CICS_{verb}", program.group(1), match, {
                    key.lower(): value for key, value in re.findall(rf"\b(COMMAREA|LENGTH|DATALENGTH)\s*\(\s*([^)]*)\)", body, re.I)
                })
        elif verb in {"SEND", "RECEIVE"}:
            mapset = re.search(rf"\bMAPSET\s*\(\s*({_WORD_RE})\s*\)", body, re.I)
            map_name = re.search(rf"\bMAP\s*\(\s*({_WORD_RE})\s*\)", body, re.I)
            if mapset or map_name:
                target = mapset.group(1) if mapset else map_name.group(1)
                add("CICS_MAPSET", target, match, {"map": map_name.group(1) if map_name else None})
        elif verb in {"START", "RETURN"}:
            transid = re.search(rf"\bTRANSID\s*\(\s*({_WORD_RE})\s*\)", body, re.I)
            if transid:
                add(f"CICS_{verb}", transid.group(1), match)

    for match in re.finditer(rf"\bEXEC\s+SQL\s+INCLUDE\s+({_WORD_RE})", masked, re.I):
        exec_spans.append(match.span())
        add("SQL_INCLUDE", match.group(1), match)
        refs[-1]["is_dynamic"] = False

    masked_no_exec = masked
    for start, end in reversed(exec_spans):
        masked_no_exec = masked_no_exec[:start] + (" " * (end - start)) + masked_no_exec[end:]
    for match in re.finditer(rf"\bCOPY\s+({_WORD_RE})(?:\s+(?:OF|IN)\s+({_WORD_RE}))?", masked_no_exec, re.I):
        target, dynamic = _resolve_literal(match.group(1), literals)
        library = match.group(2)
        refs.append({"type": "COPY", "target_name": target, "is_dynamic": False, "attributes": {"library": library}, "line": statement["line"], "end_line": statement.get("end_line", statement["line"]), "seq": seq_by_line.get(statement["line"]), "excerpt": re.sub(r"\s+", " ", text).strip()[:120]})
    for match in re.finditer(rf"\bCALL\s+({_WORD_RE})", masked_no_exec, re.I):
        add("CALL", match.group(1), match)

    if is_jcl:
        for match in re.finditer(r"\bEXEC\s+PGM\s*=\s*([A-Z0-9@$#-]+)", masked, re.I):
            add("JCL_EXEC_PGM", match.group(1), match)
            refs[-1]["is_dynamic"] = False
        for match in re.finditer(r"\bEXEC\s+([A-Z@$#][A-Z0-9@$#-]*)", masked, re.I):
            if match.group(1).upper() != "PGM":
                add("JCL_EXEC_PROC", match.group(1), match)
                refs[-1]["is_dynamic"] = False
    return refs


def scan_file(path: Path, source_root: Path, folder_hints: tuple[str, ...] = ()) -> dict[str, Any]:
    text, encoding, fallback = decode_source(path)
    lines, source_format, line_ending = _source_lines(text)
    relpath = path.relative_to(source_root).as_posix()
    file_type = _classify(path, source_root, lines, folder_hints)
    seq_by_line = {row["line"]: row["seq"] for row in lines}
    statements = _logical_statements(lines)
    refs: list[dict[str, Any]] = []
    cics_verbs: Counter[str] = Counter()
    sql_verbs: Counter[str] = Counter()
    cics_targets: set[str] = set()
    call_targets: set[str] = set()
    for statement in statements:
        masked, _ = _mask_literals(statement["text"])
        cics_verbs.update(match.group(1).upper() for match in re.finditer(r"\bEXEC\s+CICS\s+([A-Z0-9-]+)", masked, re.I))
        sql_verbs.update(match.group(1).upper() for match in re.finditer(r"\bEXEC\s+SQL\s+([A-Z0-9-]+)", masked, re.I))
        for ref in _statement_references(statement, relpath, seq_by_line, file_type == "JCL"):
            ref["source_file"] = relpath
            if ref["type"] in {"CICS_LINK", "CICS_XCTL", "CICS_LOAD"}:
                cics_targets.add(ref["target_name"])
            elif ref["type"] == "CALL":
                call_targets.add(ref["target_name"])
            refs.append(ref)

    code_lines = [row for row in lines if row["kind"] == "code"]
    names = {"programs": [], "copybook_items": [], "sections": [], "paragraphs": [], "csects": []}
    full_code = "\n".join(row["code"] for row in code_lines)
    for match in re.finditer(r"\bPROGRAM-ID\s*\.\s*([A-Z0-9_-]+)", full_code, re.I):
        names["programs"].append(match.group(1).upper())
    for match in re.finditer(r"(?m)^\s*01\s+([A-Z0-9_-]+)", full_code, re.I):
        names["copybook_items"].append(match.group(1).upper())
    for match in re.finditer(r"(?m)^\s*([A-Z0-9_-]+)\s+CSECT\b", full_code, re.I):
        names["csects"].append(match.group(1).upper())
    for match in re.finditer(r"\bCSECT\s+([A-Z0-9_-]+)", full_code, re.I):
        names["csects"].append(match.group(1).upper())
    for match in re.finditer(r"(?m)^\s*([A-Z0-9_-]+)\s+(?:SECTION|\.)", full_code, re.I):
        names["sections" if "SECTION" in match.group(0).upper() else "paragraphs"].append(match.group(1).upper())
    for key in names:
        names[key] = sorted(set(names[key]))

    counts = Counter(row["kind"] for row in lines)
    return {
        "file_id": "",
        "path": relpath,
        "name": path.name,
        "extension": path.suffix,
        "folder_hint": path.parent.name if path.parent != source_root else "",
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "encoding": encoding,
        "decode_fallback_used": fallback,
        "bom": text.startswith("\ufeff"),
        "line_ending": line_ending,
        "source_format": source_format,
        "classification": {"type": file_type, "subtype": [], "confidence": "HIGH" if file_type != "UNKNOWN" else "LOW", "reasons": [{"rule": "content_and_extension", "line": 1}]},
        "program_name": names["programs"][0] if names["programs"] else path.stem,
        "program_name_source": "PROGRAM_ID" if names["programs"] else "FILENAME",
        "line_counts": {"total": len(lines), "code": counts["code"], "comment": counts["comment"], "blank": counts["blank"], "non_code_text": counts["non_code"]},
        "defined_names": names,
        "references": refs,
        "statements": statements,
        "cics_verbs": dict(cics_verbs),
        "sql_verbs": dict(sql_verbs),
        "cics_targets": sorted(cics_targets),
        "call_targets": sorted(call_targets),
        "lines": lines,
    }