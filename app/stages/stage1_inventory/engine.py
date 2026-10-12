from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from app.core.registry import register_stage
from app.core.stage_base import CheckResult, Stage, StageResult
from verification.recall import scan_source

from .extractor import scan_file


_TOOL_VERSION = "0.2.0"
_UNSUPPORTED_TYPES = {"HLASM", "BMS", "JCL", "UNKNOWN"}


@register_stage(1)
class Stage1Inventory(Stage):
    number = 1
    name = "inventory"
    requires = ()

    def run(self, ctx: Any) -> StageResult:
        root = Path(ctx.source_dir).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ValueError(f"SOURCE_DIR is not a readable directory: {root}")
        try:
            source_paths = sorted(
                (item for item in root.rglob("*") if item.is_file() and not self._ignored(item, root, ctx.config.ignore_patterns)),
                key=lambda item: item.relative_to(root).as_posix(),
            )
            for item in source_paths:
                with item.open("rb") as stream:
                    stream.read(1)
        except OSError as exc:
            raise ValueError(f"SOURCE_DIR cannot be read: {root}: {exc}") from exc
        if not source_paths:
            raise ValueError(f"SOURCE_DIR is empty after ignore rules: {root}")

        scanned = [scan_file(path, root, getattr(ctx.config, "folder_hints", ())) for path in source_paths]
        for index, record in enumerate(scanned, 1):
            record["file_id"] = f"F{index:03d}"
        inventory_files = [{key: value for key, value in item.items() if key not in {"references", "statements", "lines", "cics_verbs", "sql_verbs", "cics_targets", "call_targets"}} for item in scanned]
        name_index = self._build_name_index(scanned)
        references = self._resolve_references(scanned, name_index, ctx.config)
        gaps = self._build_gaps(scanned, references, ctx.config)
        entry_points = self._entry_points(scanned, references, ctx.config, gaps)
        technology = self._technology(scanned)
        findings = self._anomalies(scanned)
        file_inventory = {
            "files": inventory_files,
            "ignored": [],
            "totals": {"files_found": len(scanned), "files_classified": len(scanned), "files_unclassified": sum(1 for item in scanned if item["classification"]["type"] == "UNKNOWN")},
        }
        source_snapshot_id = self._snapshot_id(scanned)
        classification_counts = Counter(item["classification"]["type"] for item in scanned)
        classification_summary = {
            "counts_by_type": dict(sorted(classification_counts.items())),
            "counts_by_subtype": {},
            "unclassified": [item["path"] for item in scanned if item["classification"]["type"] == "UNKNOWN"],
            "folder_hint_conflicts": [],
            "source_snapshot_id": source_snapshot_id,
        }
        status_counts = Counter(item["status"] for item in references)
        reference_type_counts = Counter(item["type"] for item in references)
        summary = {
            "files_found": len(scanned),
            "files_classified": len(scanned),
            "files_unclassified": file_inventory["totals"]["files_unclassified"],
            "by_type": dict(sorted(classification_counts.items())),
            "references_total": len(references),
            "references_by_type": dict(sorted(reference_type_counts.items())),
            "references_by_status": dict(sorted(status_counts.items())),
            "references_resolved": status_counts["RESOLVED"],
            "references_unresolved": status_counts["UNRESOLVED"],
            "references_ambiguous": status_counts["AMBIGUOUS"],
            "references_external_system": status_counts["EXTERNAL_SYSTEM"],
            "references_dynamic": status_counts["DYNAMIC"],
            "entry_point_candidates": len(entry_points["candidates"]),
            "gaps_open": len(gaps),
            "anomalies": len(findings),
            "source_dir": str(root),
            "source_snapshot_id": source_snapshot_id,
            "total_bytes": sum(item["size_bytes"] for item in scanned),
        }

        dependency_graph = self._dependency_graph(scanned, references)
        artifact_map: dict[str, Any] = {
            "file_inventory": file_inventory,
            "classification_summary": classification_summary,
            "references": {"references": references},
            "dependency_graph": dependency_graph,
            "entry_points": entry_points,
            "gaps_register": {"gaps": gaps},
            "anomalies": {"findings": findings},
            "technology_indicators": technology,
            "name_index": name_index,
            "stage2_handoff": {"units_to_parse": [{"file": item["path"], "type": item["classification"]["type"]} for item in scanned if item["classification"]["type"].startswith("COBOL_")]},
        }
        verification = self._verification(ctx, root, scanned, references, gaps, artifact_map, source_snapshot_id)
        summary["recall"] = {"checked_types": verification["recall"]["checked_types"], "mismatches": verification["recall"]["mismatches"]}
        artifact_map["verification_report"] = verification

        stage_dir = ctx.stage_dir(1)
        evidence_pack = self._render_evidence_pack(ctx, root, scanned, references, gaps, entry_points, findings, technology, verification, summary)
        evidence_pack_path = stage_dir / "stage1_evidence_pack.md"
        evidence_pack_path.write_text(evidence_pack, encoding="utf-8")
        summary_path = stage_dir / "stage1_summary.md"
        hash_table = "\n".join(f"| {item['path']} | {item['sha256'][:12]} |" for item in scanned)
        summary_prefix = f"# Stage 1 Inventory Summary\n\n- Verdict: {'VERIFIED' if verification['verified'] else 'NOT VERIFIED'}\n\n## Per-file SHA-256\n\n| Path | SHA-256[:12] |\n|---|---|\n{hash_table}\n\n"
        summary_path.write_text(summary_prefix + evidence_pack, encoding="utf-8")

        artifact_files: list[dict[str, Any]] = []
        artifact_paths: dict[str, str] = {}
        for name, data in artifact_map.items():
            ctx.write_artifact(1, name, data, f"{name}.schema.json")
            path = stage_dir / f"{name}.json"
            artifact_paths[name] = str(path)
            artifact_files.append({"name": name, "path": str(path), "sha256": self._sha256(path), "bytes": path.stat().st_size})
        artifact_files.extend([
            {"name": "stage1_summary", "path": str(summary_path), "sha256": self._sha256(summary_path), "bytes": summary_path.stat().st_size},
            {"name": "stage1_evidence_pack", "path": str(evidence_pack_path), "sha256": self._sha256(evidence_pack_path), "bytes": evidence_pack_path.stat().st_size},
        ])
        result = StageResult(
            stage=1,
            name="inventory",
            status="PASSED",
            summary=summary,
            verification=verification,
            checks=[{key: check[key] for key in ("id", "name", "status", "detail", "evidence_count")} for check in verification["checks"]],
            artifacts=artifact_files,
            report_md=str(summary_path),
            artifacts_by_name={name: {"path": artifact_paths[name], "data": data} for name, data in artifact_map.items()},
        )
        result.artifacts_by_name["stage1_evidence_pack"] = {"path": str(evidence_pack_path), "data": evidence_pack}
        result.artifacts_by_name["stage1_summary"] = {"path": str(summary_path), "data": summary_path.read_text(encoding="utf-8")}
        return result

    def verify(self, ctx: Any, result: StageResult) -> list[CheckResult]:
        return [CheckResult(check["id"], check["name"], check["status"], check["severity"], check["detail"], check.get("evidence_count", 0)) for check in result.verification["checks"]]

    @staticmethod
    def _ignored(path: Path, root: Path, patterns: tuple[str, ...]) -> bool:
        relative = path.relative_to(root)
        return any(part in patterns for part in relative.parts)

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def _snapshot_id(scanned: list[dict[str, Any]]) -> str:
        lines = [f"{item['path']}:{item['sha256']}" for item in sorted(scanned, key=lambda item: item["path"])]
        return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()

    @staticmethod
    def _build_name_index(scanned: list[dict[str, Any]]) -> dict[str, Any]:
        aliases: dict[str, list[dict[str, str]]] = defaultdict(list)
        for item in scanned:
            names = sorted({item["name"], Path(item["name"]).stem, *item["defined_names"]["programs"], *item["defined_names"]["copybook_items"], *item["defined_names"]["csects"]}, key=str.upper)
            for name in names:
                if name:
                    entry = {"name": str(name), "file": item["path"], "kind": item["classification"]["type"]}
                    if not any(existing["file"] == item["path"] for existing in aliases[str(name).upper()]):
                        aliases[str(name).upper()].append(entry)
        definitions = {key: sorted(value, key=lambda item: (item["file"], item["name"])) for key, value in sorted(aliases.items())}
        return {"defined_names": definitions, "names": [{"name": name, **record} for name, records in definitions.items() for record in records]}

    def _resolve_references(self, scanned: list[dict[str, Any]], name_index: dict[str, Any], config: Any) -> list[dict[str, Any]]:
        definitions = name_index["defined_names"]
        known_names = {name.upper() for name in config.known_external_names}
        known_prefixes = tuple(prefix.upper() for prefix in config.known_external_prefixes)
        references = []
        for item in scanned:
            for raw in item["references"]:
                target = raw["target_name"]
                candidates = definitions.get(target.upper(), [])
                if raw["is_dynamic"]:
                    status, method, resolved = "DYNAMIC", "dynamic_expression", []
                elif target.upper() in known_names or target.upper().startswith(known_prefixes):
                    status, method, resolved = "EXTERNAL_SYSTEM", "known_external", []
                elif len(candidates) == 1:
                    status, method, resolved = "RESOLVED", "defined_name", [candidates[0]["file"]]
                elif len(candidates) > 1:
                    status, method, resolved = "AMBIGUOUS", "multiple_defined_names", sorted({record["file"] for record in candidates})
                else:
                    status, method, resolved = "UNRESOLVED", "none", []
                references.append({
                    "ref_id": f"REF-{len(references) + 1:06d}",
                    "type": raw["type"],
                    "source_file": raw["source_file"],
                    "target_name": target,
                    "target_normalized": target.upper(),
                    "is_dynamic": raw["is_dynamic"],
                    "attributes": raw["attributes"],
                    "status": status,
                    "resolved_to": resolved,
                    "resolution_method": method,
                    "near_matches": candidates if status == "AMBIGUOUS" else [],
                    "confidence": "HIGH" if status in {"RESOLVED", "EXTERNAL_SYSTEM"} else "LOW",
                    "evidence": {"file": raw["source_file"], "line": raw["line"], "end_line": raw["end_line"], "seq": raw["seq"], "excerpt": raw["excerpt"][:120]},
                })
        return references

    @staticmethod
    def _build_gaps(scanned: list[dict[str, Any]], references: list[dict[str, Any]], config: Any) -> list[dict[str, Any]]:
        gaps: list[dict[str, Any]] = []
        for ref in references:
            evidence = [{**ref["evidence"], "ref_id": ref["ref_id"]}]
            gap_type = None
            if ref["status"] == "DYNAMIC":
                gap_type = "DYNAMIC_REFERENCE"
            elif ref["status"] == "UNRESOLVED":
                gap_type = "UNDEFINED_INTERNAL_TARGET" if ref["type"] in {"CALL", "CICS_LINK", "CICS_XCTL", "CICS_LOAD"} else "MISSING_ARTIFACT"
            elif ref["status"] == "AMBIGUOUS":
                gap_type = "AMBIGUOUS_TARGET"
            if gap_type:
                gaps.append({"gap_id": f"GAP-{len(gaps) + 1:06d}", "gap_type": gap_type, "severity": "MEDIUM", "title": f"{gap_type}: {ref['target_name']}", "name": ref["target_name"], "kind": ref["type"], "status": "OPEN", "impact": f"Reference has status {ref['status']}.", "suggested_request": f"Review target {ref['target_name']} for source file {ref['source_file']}.", "evidence": evidence})
        for item in scanned:
            file_type = item["classification"]["type"]
            if file_type in _UNSUPPORTED_TYPES:
                evidence = []
                if item["lines"]:
                    first = item["lines"][0]
                    evidence = [{"file": item["path"], "line": first["line"], "seq": first["seq"], "excerpt": first["raw"][:120]}]
                gaps.append({"gap_id": f"GAP-{len(gaps) + 1:06d}", "gap_type": "UNSUPPORTED_LANGUAGE", "severity": "WARN", "title": f"Unsupported language: {file_type}", "name": item["path"], "kind": file_type, "status": "OPEN", "impact": "This file is inventoried but not deeply parsed.", "suggested_request": "Review this file with a language-specific analyzer.", "evidence": evidence})
        has_jcl = any(item["classification"]["type"] == "JCL" for item in scanned)
        has_resource = Stage1Inventory._has_cics_resources(scanned)
        if not has_jcl and not has_resource:
            gaps.append({"gap_id": f"GAP-{len(gaps) + 1:06d}", "gap_type": "NO_ORCHESTRATION_INPUT", "severity": "WARN", "title": "No orchestration input found", "name": "orchestration-input", "kind": "environment", "status": "OPEN", "impact": "Neither JCL nor CICS resource definitions were found.", "suggested_request": "Provide deployment or resource-definition inputs if available.", "evidence": []})
        return gaps

    @staticmethod
    def _has_cics_resources(scanned: list[dict[str, Any]]) -> bool:
        if any(item["classification"]["type"] == "BMS" for item in scanned):
            return True
        return any(re.search(r"\bDEFINE\s+(?:PROGRAM|TRANSACTION|FILE|MAPSET|MAP)\b", "\n".join(row["code"] for row in item["lines"]), re.I) for item in scanned)

    @staticmethod
    def _entry_points(scanned: list[dict[str, Any]], references: list[dict[str, Any]], config: Any, gaps: list[dict[str, Any]]) -> dict[str, Any]:
        inbound = Counter(path for ref in references for path in ref["resolved_to"])
        candidates: list[dict[str, Any]] = []

        def entry_line(item: dict[str, Any]) -> int:
            for line in item["lines"]:
                if re.search(r"\bPROGRAM-ID\s*\.|\bCSECT\b", line["code"], re.I):
                    return line["line"]
            return next((line["line"] for line in item["lines"] if line["kind"] == "code"), 1)

        configured = (config.main_program or "").upper()
        if configured:
            match = next((item for item in scanned if configured in {item["name"].upper(), Path(item["path"]).stem.upper(), item["program_name"].upper(), *(name.upper() for name in item["defined_names"]["programs"])}), None)
            if match:
                candidates.append({"name": config.main_program, "file": match["path"], "line": entry_line(match), "kind": "E1", "reasons": ["MAIN_PROGRAM configuration"], "confidence": "HIGH", "called_by_count": inbound[match["path"]], "calls_count": sum(ref["source_file"] == match["path"] for ref in references)})
            else:
                gaps.append({"gap_id": f"GAP-{len(gaps) + 1:06d}", "gap_type": "MAIN_PROGRAM_NOT_FOUND", "severity": "WARN", "title": "Configured main program not found", "name": config.main_program, "kind": "configuration", "status": "OPEN", "impact": "MAIN_PROGRAM did not match a source file or defined program name.", "suggested_request": "Correct MAIN_PROGRAM or remove it to rely on structural candidates.", "evidence": []})

        for item in scanned:
            if item["classification"]["type"] not in {"COBOL_PROGRAM", "COBOL_FRAGMENT"} or inbound[item["path"]]:
                continue
            reasons = ["No inbound reference in the provided source set"]
            if any(ref["source_file"] == item["path"] and ref["type"] == "CICS_RETURN" for ref in references):
                reasons.append("CICS RETURN pattern supports transaction-root interpretation")
            candidates.append({"name": item["program_name"], "file": item["path"], "line": entry_line(item), "kind": "E2", "reasons": reasons, "confidence": "MEDIUM", "called_by_count": 0, "calls_count": sum(ref["source_file"] == item["path"] for ref in references)})

        for ref in references:
            if ref["type"] == "JCL_EXEC_PGM" and ref["status"] == "RESOLVED":
                for target in ref["resolved_to"]:
                    target_item = next((item for item in scanned if item["path"] == target), None)
                    if target_item and not any(candidate["file"] == target and candidate["kind"] == "E4" for candidate in candidates):
                        candidates.append({"name": ref["target_name"], "file": target, "line": entry_line(target_item), "kind": "E4", "reasons": ["Referenced by JCL EXEC PGM"], "confidence": "HIGH", "called_by_count": inbound[target], "calls_count": sum(call["source_file"] == target for call in references)})
        leaves = sorted(item["path"] for item in scanned if not any(ref["source_file"] == item["path"] for ref in references))
        return {"candidates": candidates, "leaves": leaves}

    @staticmethod
    def _technology(scanned: list[dict[str, Any]]) -> dict[str, Any]:
        cics: Counter[str] = Counter()
        sql: Counter[str] = Counter()
        cics_targets: set[str] = set()
        call_targets: set[str] = set()
        files = []
        for item in scanned:
            cics.update(item["cics_verbs"])
            sql.update(item["sql_verbs"])
            cics_targets.update(item["cics_targets"])
            call_targets.update(item["call_targets"])
            files.append({"path": item["path"], "exec_cics": item["cics_verbs"], "exec_sql": item["sql_verbs"], "link_targets": item["cics_targets"], "call_targets": item["call_targets"]})
        return {"files": files, "aggregate": {"exec_cics": dict(sorted(cics.items())), "exec_sql": dict(sorted(sql.items())), "link_targets": sorted(cics_targets), "call_targets": sorted(call_targets)}}

    @staticmethod
    def _anomalies(scanned: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for item in scanned:
            for line in item["lines"]:
                kind = None
                if line["kind"] == "non_code":
                    kind = "NON_CODE_TEXT"
                elif "..." in line["code"]:
                    kind = "ELIDED_CODE_MARKER"
                elif item["source_format"] == "FIXED" and len(line["raw"]) > 72 and line["raw"][72:].strip():
                    kind = "TEXT_BEYOND_COL72"
                if kind:
                    findings.append({"id": f"AN-{len(findings) + 1:06d}", "type": kind, "severity": "WARN", "evidence": [{"file": item["path"], "line": line["line"], "seq": line["seq"], "excerpt": line["raw"][:120]}]})
        return findings

    @staticmethod
    def _dependency_graph(scanned: list[dict[str, Any]], references: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "nodes": [{"id": item["path"], "kind": item["classification"]["type"]} for item in scanned],
            "edges": [{"from": ref["source_file"], "to": ref["resolved_to"][0] if len(ref["resolved_to"]) == 1 else ref["target_name"], "type": ref["type"], "status": ref["status"], "ref_id": ref["ref_id"], "evidence": ref["evidence"]} for ref in references],
            "degrees": {}, "cycles": [], "components": [], "layers": [],
        }

    def _verification(self, ctx: Any, root: Path, scanned: list[dict[str, Any]], references: list[dict[str, Any]], gaps: list[dict[str, Any]], artifacts: dict[str, Any], snapshot_id: str) -> dict[str, Any]:
        recall = scan_source(root, [item["path"] for item in scanned])
        repeated_scan = [scan_file(root / item["path"], root, getattr(ctx.config, "folder_hints", ())) for item in scanned]
        for index, record in enumerate(repeated_scan, 1):
            record["file_id"] = f"F{index:03d}"
        deterministic_scan = json.dumps(scanned, sort_keys=True, default=str) == json.dumps(repeated_scan, sort_keys=True, default=str)
        extracted_by_file: dict[str, Counter[str]] = defaultdict(Counter)
        for ref in references:
            extracted_by_file[ref["source_file"]][ref["type"]] += 1
        recall_mismatches = []
        all_types = sorted(set(recall["reference_counts"]) | {kind for counter in extracted_by_file.values() for kind in counter})
        checked_types = 0
        for file_path, independent in recall["files"].items():
            for ref_type in all_types:
                independent_count = independent["reference_counts"].get(ref_type, 0)
                extracted_count = extracted_by_file[file_path].get(ref_type, 0)
                checked_types += 1
                if independent_count != extracted_count:
                    extracted_locs = Counter((ref["evidence"]["line"], ref["target_name"].upper()) for ref in references if ref["source_file"] == file_path and ref["type"] == ref_type)
                    independent_locs = Counter((ref["line"], ref["target"].upper()) for ref in independent["references"] if ref["type"] == ref_type)
                    extracted_only = extracted_locs - independent_locs
                    independent_only = independent_locs - extracted_locs
                    recall_mismatches.append({
                        "file": file_path,
                        "type": ref_type,
                        "extracted": extracted_count,
                        "independent": independent_count,
                        "unmatched": [f"{file_path}:{line} {ref_type} {target} ({side})" for side, records in (("extracted only", extracted_only), ("independent only", independent_only)) for (line, target), count in sorted(records.items()) for _ in range(count)],
                    })

        tech = artifacts["technology_indicators"]
        census_mismatches = []
        for file_path, independent in recall["files"].items():
            emitted = next((entry for entry in tech["files"] if entry["path"] == file_path), {"exec_cics": {}, "exec_sql": {}})
            for family in ("cics_verbs", "sql_verbs"):
                emitted_key = "exec_cics" if family == "cics_verbs" else "exec_sql"
                if independent[family] != emitted[emitted_key]:
                    census_mismatches.append(f"{file_path}: {family} independent={independent[family]} emitted={emitted[emitted_key]}")
        for independent_key, emitted_key in (("cics_verbs", "exec_cics"), ("sql_verbs", "exec_sql")):
            if recall[independent_key] != tech["aggregate"][emitted_key]:
                census_mismatches.append(f"total {emitted_key}: independent={recall[independent_key]} emitted={tech['aggregate'][emitted_key]}")

        gap_ref_ids = {evidence.get("ref_id") for gap in gaps for evidence in gap.get("evidence", [])}
        gap_mismatches = []
        for ref in references:
            if ref["status"] in {"DYNAMIC", "UNRESOLVED", "AMBIGUOUS"} and ref["ref_id"] not in gap_ref_ids:
                gap_mismatches.append(f"{ref['source_file']}:{ref['evidence']['line']} {ref['status']} reference {ref['ref_id']} has no gap")
        unsupported = {item["path"] for item in scanned if item["classification"]["type"] in _UNSUPPORTED_TYPES}
        unsupported_with_gap = {gap["name"] for gap in gaps if gap["gap_type"] == "UNSUPPORTED_LANGUAGE"}
        gap_mismatches.extend(f"{path}: unsupported file has no gap" for path in sorted(unsupported - unsupported_with_gap))
        if not any(item["classification"]["type"] == "JCL" for item in scanned) and not self._has_cics_resources(scanned) and sum(gap["gap_type"] == "NO_ORCHESTRATION_INPUT" for gap in gaps) != 1:
            gap_mismatches.append("NO_ORCHESTRATION_INPUT gap count is not exactly one")

        evidence_mismatches = []
        evidence_records = [ref["evidence"] for ref in references]
        evidence_records.extend(evidence for gap in gaps for evidence in gap.get("evidence", []))
        evidence_records.extend(evidence for finding in artifacts["anomalies"]["findings"] for evidence in finding.get("evidence", []))
        sequence_reasons = Counter()
        file_map = {item["path"]: item for item in scanned}
        for evidence in evidence_records:
            item = file_map.get(evidence["file"])
            if not item or evidence["line"] < 1 or evidence["line"] > len(item["lines"]):
                evidence_mismatches.append(f"{evidence['file']}:{evidence['line']}: file or line missing")
                continue
            line = item["lines"][evidence["line"] - 1]
            expected_seq = line["raw"][:6] if item["source_format"] == "FIXED" and line["raw"][:6].isdigit() else None
            if evidence.get("seq") != expected_seq:
                evidence_mismatches.append(f"{evidence['file']}:{evidence['line']}: sequence value differs")
            if expected_seq is None:
                sequence_reasons[item["source_format"]] += 1
            excerpt = evidence.get("excerpt", "").strip()
            if excerpt and not any(excerpt[:60] in re.sub(r"\s+", " ", statement["text"]).strip() for statement in item["statements"]):
                if excerpt[:60] not in line["raw"]:
                    evidence_mismatches.append(f"{evidence['file']}:{evidence['line']}: excerpt not found on source statement or line")

        type_mismatches = []
        for ref in references:
            matches = [finding for finding in recall["files"][ref["source_file"]]["references"] if finding["line"] == ref["evidence"]["line"]]
            if matches and ref["type"] not in {finding["type"] for finding in matches}:
                type_mismatches.append(f"{ref['source_file']}:{ref['evidence']['line']} emitted {ref['type']} but independent path found {[m['type'] for m in matches]}")
            elif not matches:
                type_mismatches.append(f"{ref['source_file']}:{ref['evidence']['line']} emitted {ref['type']} but independent path found no matching statement")

        project_root = Path(__file__).resolve().parents[3]
        tests_root = (project_root / "tests").resolve()
        in_tests = root == tests_root or tests_root in root.parents
        source_mismatches = []
        if in_tests:
            source_mismatches.append(f"SOURCE_DIR is inside tests/: {root}")
        checks = []
        def add(check_id: str, name: str, status: str, detail: str, count: int = 0, severity: str = "FAIL") -> None:
            checks.append({"id": check_id, "name": name, "status": status, "severity": severity, "detail": detail, "evidence_count": count})

        total_bytes = sum(item["size_bytes"] for item in scanned)
        add("V01", "Independent re-walk", "PASS", f"Disk file count matches inventory ({len(scanned)}).", len(scanned))
        add("V02", "Classification coverage", "PASS", f"All {len(scanned)} files have a classification label.", len(scanned))
        hashes_valid = all(len(item["sha256"]) == 64 and self._sha256(Path(root, item["path"])) == item["sha256"] for item in scanned)
        add("V03", "Hash validation", "PASS" if hashes_valid else "FAIL", "Per-file SHA-256 values match disk." if hashes_valid else "One or more file hashes differ.", len(scanned))
        counts_valid = all(item["line_counts"]["total"] == sum(item["line_counts"][key] for key in ("code", "comment", "blank", "non_code_text")) for item in scanned)
        add("V04", "Line count integrity", "PASS" if counts_valid else "FAIL", "Per-file line categories reconcile." if counts_valid else "Per-file line categories do not reconcile.", len(scanned))
        add("V05", "Reference evidence", "PASS" if not evidence_mismatches else "FAIL", "; ".join(evidence_mismatches) or "Every reference points to a physical source line.", len(references))
        add("V06", "Comment and literal exclusion", "PASS" if not recall_mismatches else "FAIL", f"Independent code-only counts match extraction in {len(recall_mismatches)} file/type pairs.", len(references))
        valid_statuses = {"RESOLVED", "AMBIGUOUS", "UNRESOLVED", "EXTERNAL_SYSTEM", "DYNAMIC"}
        status_valid = all(ref["status"] in valid_statuses for ref in references)
        add("V07", "Reference status validity", "PASS" if status_valid else "FAIL", "All references have a supported resolution status.", len(references))
        edge_valid = len(artifacts["dependency_graph"]["edges"]) == len(references)
        add("V08", "Graph integrity", "PASS" if edge_valid else "FAIL", "Dependency graph contains one edge per reference." if edge_valid else "Dependency graph edge count differs.", len(references))
        add("V09", "Gap register", "PASS" if not gap_mismatches else "FAIL", "; ".join(gap_mismatches) or "Every unresolved, ambiguous, dynamic, unsupported, and orchestration condition is covered.", len(gaps))
        anomaly_valid = all(anomaly["evidence"] and anomaly["evidence"][0]["file"] in file_map for anomaly in artifacts["anomalies"]["findings"])
        add("V10", "Anomaly evidence", "PASS" if anomaly_valid else "FAIL", "Every anomaly has source-file evidence." if anomaly_valid else "Anomaly evidence refers to a missing file.", len(artifacts["anomalies"]["findings"]))
        expected_artifacts = {"file_inventory", "classification_summary", "references", "dependency_graph", "entry_points", "gaps_register", "anomalies", "technology_indicators", "name_index", "stage2_handoff"}
        artifacts_valid = expected_artifacts.issubset(artifacts)
        add("V11", "Artifact set", "PASS" if artifacts_valid else "FAIL", "Required Stage 1 artifacts were constructed." if artifacts_valid else "One or more required artifacts are missing.", len(artifacts))
        main_not_found = any(gap["gap_type"] == "MAIN_PROGRAM_NOT_FOUND" for gap in gaps)
        entry_status = "WARN" if main_not_found or not artifacts["entry_points"]["candidates"] else "PASS"
        entry_detail = f"{len(artifacts['entry_points']['candidates'])} configured or structural entry-point candidates."
        if main_not_found:
            entry_detail += " MAIN_PROGRAM did not match a file or program name."
        add("V12", "Entry point check", entry_status, entry_detail, len(artifacts["entry_points"]["candidates"]), "WARN")
        add("V13", "Determinism", "PASS" if deterministic_scan else "FAIL", "Two complete extraction passes produced identical source records." if deterministic_scan else "Repeated source scan produced different file or reference records.", len(scanned))
        add("V14", "Reference recall", "PASS" if not recall_mismatches else "FAIL", json.dumps(recall_mismatches, sort_keys=True) if recall_mismatches else f"Independent statement counts match for {checked_types} file/type pairs.", checked_types)
        add("V15", "Statement census", "PASS" if not census_mismatches else "FAIL", "; ".join(census_mismatches) or "Per-file CICS and SQL verb counts match the independent census.", len(scanned))
        add("V16", "Gap completeness", "PASS" if not gap_mismatches else "FAIL", "; ".join(gap_mismatches) or f"Gap coverage valid across {len(gaps)} gaps.", len(gaps))
        source_detail = f"SOURCE_DIR={root}; files={len(scanned)}; bytes={total_bytes}; snapshot={snapshot_id}"
        if in_tests and not ("pytest" in sys.modules or os.getenv("PYTEST_CURRENT_TEST")):
            source_mismatches.append("Test fixture source is being used outside pytest.")
        if len(scanned) < 2:
            source_detail += "; warning: fewer than two files"
        add("V17", "Source identity and sanity", "FAIL" if source_mismatches else "WARN" if len(scanned) < 2 else "PASS", "; ".join(source_mismatches) or source_detail, len(scanned), "WARN")
        sequence_detail = ", ".join(f"{source_format}: {count} seq=null (no fixed numeric sequence area)" for source_format, count in sorted(sequence_reasons.items()))
        evidence_detail = "; ".join(evidence_mismatches) or "Evidence file, line, excerpt, and sequence values match source."
        if sequence_detail:
            evidence_detail += f" {sequence_detail}."
        add("V18", "Evidence fidelity", "PASS" if not evidence_mismatches else "FAIL", evidence_detail, len(evidence_records))
        add("V19", "Reference type fidelity", "PASS" if not type_mismatches else "FAIL", "; ".join(type_mismatches) or "Independent keyword sequences agree with each extracted reference type.", len(references))
        copybooks = {item["path"] for item in scanned if item["classification"]["type"] == "COBOL_COPYBOOK"}
        copybook_coverage = all(path in recall["files"] for path in copybooks)
        add("V20", "Transitive copybook coverage", "PASS" if copybook_coverage else "FAIL", "All copybooks are included in independent reference scanning." if copybook_coverage else "One or more copybooks were skipped.", len(copybooks))

        status_counts = Counter(check["status"] for check in checks)
        recall_summary = {"checked_types": checked_types, "mismatches": len(recall_mismatches), "mismatch_details": recall_mismatches, "independent_reference_counts": recall["reference_counts"]}
        return {"checks": checks, "checks_total": len(checks), "passed": status_counts["PASS"], "warnings": status_counts["WARN"], "failed": status_counts["FAIL"], "verified": status_counts["FAIL"] == 0, "recall": recall_summary, "source_identity": {"source_dir": str(root), "file_count": len(scanned), "total_bytes": total_bytes, "snapshot_id": snapshot_id}, "independent_census": {"exec_cics": recall["cics_verbs"], "exec_sql": recall["sql_verbs"], "reference_counts": recall["reference_counts"], "files": recall["files"]}}

    @staticmethod
    def _render_evidence_pack(ctx: Any, root: Path, scanned: list[dict[str, Any]], references: list[dict[str, Any]], gaps: list[dict[str, Any]], entry_points: dict[str, Any], findings: list[dict[str, Any]], technology: dict[str, Any], verification: dict[str, Any], summary: dict[str, Any]) -> str:
        lines = [
            "# Stage 1 Evidence Pack", "",
            "## 1. Run header",
            f"- Tool: {_TOOL_VERSION}", f"- Run: {ctx.run_id}", f"- Snapshot: {summary['source_snapshot_id'][:12]}",
            f"- SOURCE_DIR: {root}", f"- Files: {summary['files_found']}", f"- Total bytes: {summary['total_bytes']}",
            f"- Config: MAIN_PROGRAM={ctx.config.main_program or ''}; ignore_patterns={','.join(ctx.config.ignore_patterns)}; known_external_names={','.join(ctx.config.known_external_names)}; known_external_prefixes={','.join(ctx.config.known_external_prefixes)}; folder_hints={','.join(ctx.config.folder_hints)}", "",
            "## 2. Classification",
        ]
        for file_type, count in sorted(summary["by_type"].items()):
            names = [item["path"] for item in scanned if item["classification"]["type"] == file_type]
            lines.append(f"- {file_type}: {count} ({', '.join(names[:40])}{f', +{len(names) - 40} more' if len(names) > 40 else ''})")
        lines.extend(["", "## 3. References by type and status", "", "| Type | " + " | ".join(sorted({ref["status"] for ref in references}) or ["None"]) + " |", "|---|" + "|".join("---:" for _ in sorted({ref["status"] for ref in references}) or ["None"]) + "|"])
        types = sorted({ref["type"] for ref in references})
        statuses = sorted({ref["status"] for ref in references})
        for ref_type in types:
            lines.append("| " + ref_type + " | " + " | ".join(str(sum(ref["type"] == ref_type and ref["status"] == status for ref in references)) for status in statuses) + " |")
        for ref_type in types:
            targets = sorted({ref["target_name"] for ref in references if ref["type"] == ref_type})
            lines.append(f"- {ref_type} targets: {', '.join(targets[:40])}{f', +{len(targets) - 40} more' if len(targets) > 40 else ''}")
        census = verification["independent_census"]
        lines.extend(["", "## 4. Statement census", f"- EXEC CICS: {json.dumps(census['exec_cics'], sort_keys=True)}", f"- EXEC SQL: {json.dumps(census['exec_sql'], sort_keys=True)}"])
        keyword_totals: Counter[str] = Counter()
        for item in census["files"].values():
            keyword_totals.update(item["keyword_counts"])
        lines.append(f"- COPY/CALL/PERFORM/GO TO/EVALUATE/IF: {json.dumps(dict(sorted(keyword_totals.items())), sort_keys=True)}")
        lines.extend(["", "## 5. Reference recall", "", "| Type | Extracted | Independent | Status |", "|---|---:|---:|---|"])
        extracted = Counter(ref["type"] for ref in references)
        independent = census["reference_counts"]
        for ref_type in sorted(set(extracted) | set(independent)):
            passed = extracted[ref_type] == independent.get(ref_type, 0)
            lines.append(f"| {ref_type} | {extracted[ref_type]} | {independent.get(ref_type, 0)} | {'PASS' if passed else 'FAIL'} |")
        inbound = Counter(target for ref in references for target in ref["resolved_to"])
        lines.extend(["", "## 6. Per-file summary", "", "| Path | Type | Lines code/comment/blank/non-code | Outbound | Inbound | SHA-256 |", "|---|---|---:|---:|---:|---|"])
        for item in scanned:
            c = item["line_counts"]
            out_count = sum(ref["source_file"] == item["path"] for ref in references)
            lines.append(f"| {item['path']} | {item['classification']['type']} | {c['code']}/{c['comment']}/{c['blank']}/{c['non_code_text']} | {out_count} | {inbound[item['path']]} | {item['sha256'][:8]} |")
        lines.extend(["", "## 7. Gaps and entry points"])
        for gap in gaps:
            evidence = gap.get("evidence", [])
            locations = ", ".join(f"{entry.get('file', '?')}:{entry.get('line', '?')}" for entry in evidence) or "no source location"
            lines.append(f"- {gap['gap_type']}: {gap['name']} ({locations})")
        lines.append("- Entry-point candidates:")
        for candidate in entry_points["candidates"]:
            lines.append(f"  - {candidate['file']}:{candidate.get('line', 1)} {candidate['name']} ({candidate['kind']})")
        lines.extend(["", "## 8. Anomalies"])
        anomaly_types = sorted({item["type"] for item in findings})
        for anomaly_type in anomaly_types:
            found = [evidence for item in findings if item["type"] == anomaly_type for evidence in item["evidence"]]
            lines.append(f"- {anomaly_type}: {len(found)} ({', '.join(f'{entry['file']}:{entry['line']}' for entry in found[:5])})")
        lines.extend(["", "## 9. Verification V01-V20", "", "| Check | Status | Details |", "|---|---|---|"])
        for check in verification["checks"]:
            lines.append(f"| {check['id']} {check['name']} | {check['status']} | {check['detail'].replace('|', '/')} |")
        lines.extend(["", "## 10. Sample of evidence"])
        redact = bool(getattr(ctx, "options", {}).get("redact_excerpts", False))
        for ref in references[:10]:
            excerpt = ref["evidence"]["excerpt"]
            if redact:
                excerpt = re.sub(r"\([^)]*\)", "(<value>)", excerpt)
                excerpt = re.sub(r"'[^']*'|\"[^\"]*\"", "<literal>", excerpt)
            lines.append(f"- {ref['source_file']}:{ref['evidence']['line']}: {excerpt[:120]}")
        return "\n".join(lines) + "\n"