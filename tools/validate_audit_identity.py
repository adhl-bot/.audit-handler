#!/usr/bin/env python3
"""
Validate Tenable/Nessus .audit visible control identity.

The description field is treated as the primary visible identity of a
reportable control. This script intentionally validates spaces and escaping
strictly because changing even one character changes the identity surfaced by
Tenable.

Fields are attached to the nearest open reportable Tenable block so nested
conditional checks do not leak their description/reference into an outer
container.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


DESCRIPTION_RE = re.compile(
    r"^\[(?P<control_id>\d+(?:\.\d+)*)\]"
    r"\[(?P<os>MS|OL|N/A)\]"
    r"\[(?P<os_version>2016|2019|2022|W11|8|N/A)\]"
    r"\[(?P<role>DM|DC|N/A)\]"
    r"\[(?P<benchmark>v\d+\.\d+\.\d+)\]"
    r"\[(?P<level>L\d+)\] "
    r"(?P<title>\S.*)$"
)

TAG_OPEN_RE = re.compile(r"^\s*#?\s*<(?P<tag>if|condition|then|else|report|custom_item|item)\b", re.I)
TAG_CLOSE_RE = re.compile(r"^\s*#?\s*</(?P<tag>if|condition|then|else|report|custom_item|item)>\s*$", re.I)
FIELD_RE = re.compile(r"^\s*#?\s*(?P<key>description|reference)\s*:\s*(?P<value>.*)$", re.I)

REPORTABLE_TAGS = {"custom_item", "item", "report"}
STRUCTURAL_TAGS = {"if", "condition", "then", "else", "custom_item", "item", "report"}
REQUIRED_COMMON_REFERENCE = {
    "CONTROL_IG": re.compile(r"(?:^|,)CONTROL_IG\|IG\d+(?:,|$)"),
    "CONTROL_INTERNAL_VERSION": re.compile(r"(?:^|,)CONTROL_INTERNAL_VERSION\|\d+(?:,|$)"),
    "CONTROL_CUSTOMER": re.compile(r"(?:^|,)CONTROL_CUSTOMER\|(true|false)(?:,|$)"),
    "CONTROL_CIS": re.compile(r"(?:^|,)CONTROL_CIS\|(true|false)(?:,|$)"),
}
REQUIRED_WINDOWS_SERVER_REFERENCE = {
    "CONTROL_MS_ONLY": re.compile(r"(?:^|,)CONTROL_MS_ONLY\|(true|false)(?:,|$)"),
    "CONTROL_DC_ONLY": re.compile(r"(?:^|,)CONTROL_DC_ONLY\|(true|false)(?:,|$)"),
}


@dataclass
class FieldValue:
    raw: str
    value: str
    quote: str
    line: int


@dataclass
class Block:
    tag: str
    file: Path
    start_line: int
    context: tuple[str, ...]
    commented_start: bool
    end_line: int | None = None
    description: FieldValue | None = None
    reference: FieldValue | None = None
    lines: list[str] = field(default_factory=list)

    @property
    def inside_condition(self) -> bool:
        return "condition" in self.context


@dataclass
class Issue:
    file: str
    line: int
    code: str
    detail: str
    description: str = ""


def strip_field_value(raw: str) -> tuple[str, str]:
    value = raw.strip()
    quote = ""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        quote = value[0]
        value = value[1:-1]
    return value, quote


def parse_auxiliary_doc(path: Path) -> set[tuple[str, int]]:
    documented: set[tuple[str, int]] = set()
    if not path.exists():
        return documented

    current_file: str | None = None
    header_re = re.compile(r"^###\s+(?P<file>.+\.audit)\s*$")
    row_re = re.compile(r"^\|\s*(?P<line>\d+)\s*\|")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        header = header_re.match(line)
        if header:
            current_file = header.group("file")
            continue
        row = row_re.match(line)
        if current_file and row:
            documented.add((current_file, int(row.group("line"))))
    return documented


def iter_audit_blocks(path: Path) -> list[Block]:
    blocks: list[Block] = []
    stack: list[tuple[str, int | None]] = []
    active_block_indices: list[int] = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    for idx, line in enumerate(lines, start=1):
        close_match = TAG_CLOSE_RE.match(line)
        if close_match:
            tag = close_match.group("tag").lower()
            for block_index in active_block_indices:
                blocks[block_index].lines.append(line)

            while stack:
                popped_tag, block_index = stack.pop()
                if block_index is not None and block_index in active_block_indices:
                    active_block_indices.remove(block_index)
                    blocks[block_index].end_line = idx
                if popped_tag == tag:
                    break
            continue

        open_match = TAG_OPEN_RE.match(line)
        if open_match:
            tag = open_match.group("tag").lower()
            if tag in STRUCTURAL_TAGS:
                block_index: int | None = None
                if tag in REPORTABLE_TAGS:
                    block = Block(
                        tag=tag,
                        file=path,
                        start_line=idx,
                        context=tuple(item[0] for item in stack),
                        commented_start=bool(re.match(r"^\s*#", line)),
                        lines=[line],
                    )
                    blocks.append(block)
                    block_index = len(blocks) - 1
                    active_block_indices.append(block_index)

                for active_index in active_block_indices:
                    if active_index != block_index:
                        blocks[active_index].lines.append(line)

                stack.append((tag, block_index))
                continue

        field_match = FIELD_RE.match(line)
        target_block_index: int | None = None
        if field_match:
            for _, block_index in reversed(stack):
                if block_index is not None:
                    target_block_index = block_index
                    break

        for block_index in active_block_indices:
            blocks[block_index].lines.append(line)

        if field_match and target_block_index is not None:
            block = blocks[target_block_index]
            key = field_match.group("key").lower()
            raw_value = field_match.group("value")
            value, quote = strip_field_value(raw_value)
            field_value = FieldValue(raw=raw_value.strip(), value=value, quote=quote, line=idx)
            if key == "description" and block.description is None:
                block.description = field_value
            elif key == "reference" and block.reference is None:
                block.reference = field_value

    return blocks


def is_windows_server(match: re.Match[str]) -> bool:
    return match.group("os") == "MS" and match.group("os_version") in {"2016", "2019", "2022"}


def is_windows11_or_linux(match: re.Match[str]) -> bool:
    return (match.group("os") == "MS" and match.group("os_version") == "W11") or match.group("os") == "OL"


def add_issue(issues: list[Issue], file: str, line: int, code: str, detail: str, description: str = "") -> None:
    issues.append(Issue(file=file, line=line, code=code, detail=detail, description=description))


def validate_description_identity(
    issues: list[Issue],
    file_name: str,
    line: int,
    raw_value: str,
    value: str,
    quote: str,
    prefix: str = "DESCRIPTION",
) -> re.Match[str] | None:
    if prefix == "DESCRIPTION" and quote != '"':
        add_issue(
            issues,
            file_name,
            line,
            f"{prefix}_NOT_DOUBLE_QUOTED",
            'El description reportable debe delimitarse con comillas dobles exteriores (")',
            value,
        )

    if re.search(r"\\['\"]", value) or re.search(r"\\['\"]", raw_value):
        add_issue(
            issues,
            file_name,
            line,
            f"{prefix}_ESCAPED_QUOTE",
            "El description contiene comillas escapadas con backslash; Tenable puede exponerlas como parte del nombre",
            value,
        )

    if quote == "'" and "'" in value:
        add_issue(
            issues,
            file_name,
            line,
            f"{prefix}_SINGLE_QUOTED_WITH_APOSTROPHE",
            "El description esta delimitado con comilla simple y el valor contiene apostrofes/comillas simples",
            value,
        )

    if re.search(r" {2,}", value):
        add_issue(
            issues,
            file_name,
            line,
            f"{prefix}_CONSECUTIVE_SPACES",
            "El description contiene espacios consecutivos; cada espacio forma parte del ID visible",
            value,
        )

    if re.search(r"\[IG\d+\]", value):
        add_issue(issues, file_name, line, f"{prefix}_IG_IN_DESCRIPTION", "IG no debe estar en description", value)

    if re.search(r"\]\[L\d+\]\s+\([Ll]\d+\)", value):
        add_issue(
            issues,
            file_name,
            line,
            f"{prefix}_DUPLICATE_LEVEL",
            "El nivel no debe duplicarse como [Lx] (Lx)",
            value,
        )

    if re.search(r"CONTROL_|CUSTOMER|MS_ONLY|DC_ONLY|INTERNAL_VERSION", value):
        add_issue(
            issues,
            file_name,
            line,
            f"{prefix}_REFERENCE_FIELD_IN_DESCRIPTION",
            "Campos de reference no deben aparecer en description",
            value,
        )

    if re.search(r"\$desc|TODO|FIXME|PLACEHOLDER|TBD", value, re.I):
        add_issue(issues, file_name, line, f"{prefix}_PLACEHOLDER", "Texto placeholder o marcador tecnico en description", value)

    match = DESCRIPTION_RE.match(value)
    if not match:
        separator_match = re.match(
            r"^\[\d+(?:\.\d+)*\]\[(?:MS|OL|N/A)\]\[(?:2016|2019|2022|W11|8|N/A)\]\[(?:DM|DC|N/A)\]\[v\d+\.\d+\.\d+\]\[L\d+\](?P<sep>\s*)",
            value,
        )
        if separator_match and separator_match.group("sep") != " ":
            add_issue(
                issues,
                file_name,
                line,
                f"{prefix}_BAD_LEVEL_TITLE_SEPARATOR",
                "Debe haber exactamente un espacio entre [LEVEL] y el titulo",
                value,
            )
        else:
            add_issue(issues, file_name, line, f"{prefix}_BAD_NAMING", "No sigue la naming convention completa", value)
        return None

    title = match.group("title")
    if title != title.strip():
        add_issue(issues, file_name, line, f"{prefix}_TITLE_TRIM", "El titulo tiene espacios al inicio o final", value)

    return match


def validate_reference(
    issues: list[Issue],
    block: Block,
    description_match: re.Match[str],
) -> None:
    file_name = block.file.name
    desc_value = block.description.value if block.description else ""
    if block.reference is None:
        add_issue(issues, file_name, block.start_line, "REFERENCE_MISSING", "Control reportable sin campo reference", desc_value)
        return

    reference = block.reference.value
    if block.reference.quote != '"':
        add_issue(
            issues,
            file_name,
            block.reference.line,
            "REFERENCE_NOT_DOUBLE_QUOTED",
            'El campo reference de controles reportables debe delimitarse con comillas dobles exteriores (")',
            desc_value,
        )

    checks = dict(REQUIRED_COMMON_REFERENCE)
    if is_windows_server(description_match):
        checks.update(REQUIRED_WINDOWS_SERVER_REFERENCE)

    for field_name, field_re in checks.items():
        if not field_re.search(reference):
            add_issue(
                issues,
                file_name,
                block.reference.line,
                "REFERENCE_FIELD_MISSING_OR_BAD",
                f"Falta o tiene formato invalido: {field_name}",
                desc_value,
            )

    if is_windows11_or_linux(description_match) and (
        "CONTROL_MS_ONLY|" in reference or "CONTROL_DC_ONLY|" in reference
    ):
        add_issue(
            issues,
            file_name,
            block.reference.line,
            "REFERENCE_WINDOWS_SERVER_FIELD_NOT_ALLOWED",
            "Windows 11 y Linux no deben tener CONTROL_MS_ONLY ni CONTROL_DC_ONLY",
            desc_value,
        )


def validate_audit_file(path: Path, documented_aux: set[tuple[str, int]]) -> tuple[list[Issue], dict[str, int]]:
    issues: list[Issue] = []
    stats = {
        "blocks": 0,
        "reportable": 0,
        "auxiliary": 0,
        "bad": 0,
    }

    for block in iter_audit_blocks(path):
        stats["blocks"] += 1
        if block.description is None:
            continue

        desc = block.description
        documented = (path.name, desc.line) in documented_aux
        match = DESCRIPTION_RE.match(desc.value)
        internal_aux = block.inside_condition or documented

        if not match and internal_aux:
            stats["auxiliary"] += 1
            continue

        if not match and not internal_aux:
            add_issue(
                issues,
                path.name,
                desc.line,
                "REPORTABLE_DESCRIPTION_WITHOUT_NAMING",
                "Bloque terminal con description sin naming convention y no documentado como auxiliar",
                desc.value,
            )
            stats["bad"] += 1
            continue

        if match:
            stats["reportable"] += 1
            strict_match = validate_description_identity(
                issues=issues,
                file_name=path.name,
                line=desc.line,
                raw_value=desc.raw,
                value=desc.value,
                quote=desc.quote,
            )
            if strict_match:
                validate_reference(issues, block, strict_match)

    stats["bad"] = len(issues)
    return issues, stats


def validate_summary_csv(path: Path) -> tuple[list[Issue], dict[str, int]]:
    issues: list[Issue] = []
    stats = {"rows": 0, "named": 0, "bad": 0}

    with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "Plugin Name" not in reader.fieldnames:
            add_issue(issues, path.name, 1, "SUMMARY_MISSING_PLUGIN_NAME", "El CSV no contiene la columna Plugin Name")
            stats["bad"] = len(issues)
            return issues, stats

        seen_plugins: dict[str, int] = {}
        seen_names: dict[str, int] = {}
        for row_index, row in enumerate(reader, start=2):
            stats["rows"] += 1
            plugin = (row.get("Plugin") or "").strip()
            name = row.get("Plugin Name") or ""
            if not plugin:
                add_issue(issues, path.name, row_index, "SUMMARY_EMPTY_PLUGIN", "Plugin vacio", name)
            elif plugin in seen_plugins:
                add_issue(issues, path.name, row_index, "SUMMARY_DUPLICATE_PLUGIN", f"Plugin duplicado; primera aparicion en linea {seen_plugins[plugin]}", name)
            else:
                seen_plugins[plugin] = row_index

            if not name.strip():
                add_issue(issues, path.name, row_index, "SUMMARY_EMPTY_PLUGIN_NAME", "Plugin Name vacio")
                continue
            if name in seen_names:
                add_issue(issues, path.name, row_index, "SUMMARY_DUPLICATE_PLUGIN_NAME", f"Plugin Name duplicado; primera aparicion en linea {seen_names[name]}", name)
            else:
                seen_names[name] = row_index

            match = validate_description_identity(
                issues=issues,
                file_name=path.name,
                line=row_index,
                raw_value=name,
                value=name,
                quote="",
                prefix="SUMMARY_DESCRIPTION",
            )
            if match:
                stats["named"] += 1

    stats["bad"] = len(issues)
    return issues, stats


def write_report(report_path: Path, issues: list[Issue], stats: dict[str, dict[str, int]]) -> None:
    payload = {
        "stats": stats,
        "issue_count": len(issues),
        "issues": [issue.__dict__ for issue in issues],
    }
    report_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate .audit reportable control identity.")
    parser.add_argument("--audit-dir", default="audits/audits_uniq_id", help="Directory containing uniqueID .audit files.")
    parser.add_argument("--audit", action="append", default=[], help="Specific .audit file to validate. Can be repeated.")
    parser.add_argument("--auxiliary-doc", default="auxiliary_descriptions_without_unique_naming.md", help="Markdown file documenting auxiliary descriptions.")
    parser.add_argument("--summary", action="append", default=[], help="Optional Tenable CSV summary to validate by Plugin Name. Can be repeated.")
    parser.add_argument("--json-report", default="", help="Optional JSON report output path.")
    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = parse_args(argv)
    documented_aux = parse_auxiliary_doc(Path(args.auxiliary_doc))

    audit_files = [Path(item) for item in args.audit]
    if not audit_files:
        audit_dir = Path(args.audit_dir)
        audit_files = sorted(audit_dir.glob("*.audit"))

    all_issues: list[Issue] = []
    all_stats: dict[str, dict[str, int]] = {}

    for audit_file in audit_files:
        issues, stats = validate_audit_file(audit_file, documented_aux)
        all_issues.extend(issues)
        all_stats[audit_file.name] = stats

    for summary_file in args.summary:
        path = Path(summary_file)
        issues, stats = validate_summary_csv(path)
        all_issues.extend(issues)
        all_stats[path.name] = stats

    print("Resumen:")
    for name, stats in all_stats.items():
        stat_text = ", ".join(f"{key}={value}" for key, value in stats.items())
        print(f"- {name}: {stat_text}")

    if args.json_report:
        write_report(Path(args.json_report), all_issues, all_stats)
        print(f"\nReporte JSON: {args.json_report}")

    if all_issues:
        print(f"\nIncidencias encontradas: {len(all_issues)}")
        for issue in all_issues:
            print(f"{issue.file}:{issue.line}: {issue.code}: {issue.detail}")
            if issue.description:
                print(f"  {issue.description}")
        return 1

    print("\nOK: validacion de identidad completada sin incidencias.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
