#!/usr/bin/env python3
"""
Canonical validator for Tenable/Nessus .audit files in this project.

The validator has three responsibilities:
- Parse Tenable structures so reportable controls are separated from silent
  condition checks.
- Validate the visible naming convention as a stable identity.
- Validate enriched CONTROL_* metadata using a project config file.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = PROJECT_ROOT / "tools" / "validator_config.json"
TAG_NAMES = "check_type|group_policy|if|condition|then|else|report|custom_item|item"
TAG_RE = re.compile(
    rf"^\s*(?P<comment>#?)\s*<(?P<close>/)?(?P<tag>{TAG_NAMES})(?P<header>(?=\s|>|:|type\s*:|$).*)",
    re.I,
)
FIELD_RE = re.compile(r"^\s*(?P<comment>#?)\s*(?P<key>[A-Za-z0-9_]+)\s*:\s*(?P<value>.*)$")
TAG_ATTR_RE = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<value>\"[^\"]*\"|'[^']*'|[^\s>]+)")
DESCRIPTION_RE = re.compile(
    r"^\[(?P<control_id>\d+(?:\.\d+)*)\]"
    r"\[(?P<os>[^\[\]]+)\]"
    r"\[(?P<os_version>[^\[\]]+)\]"
    r"\[(?P<role>[^\[\]]+)\]"
    r"\[(?P<benchmark_version>v\d+\.\d+\.\d+)\]"
    r"\[(?P<level>L\d+)\] "
    r"(?P<title>\S.*)$"
)
REPORTABLE_TAGS = {"custom_item", "item", "report"}
STRUCTURAL_TAGS = {"if", "condition", "then", "else", "custom_item", "item", "report"}


@dataclass
class Issue:
    file: str
    line: int
    code: str
    detail: str
    description: str = ""
    field_name: str = ""
    bad_value: str = ""


@dataclass
class FieldValue:
    raw: str
    value: str
    quote: str
    line: int
    end_line: int
    commented: bool
    quote_closed: bool = True


@dataclass
class Block:
    tag: str
    file: Path
    start_line: int
    context: tuple[str, ...]
    commented_start: bool
    end_line: int | None = None
    tag_attrs: dict[str, str] = field(default_factory=dict)
    fields: dict[str, FieldValue] = field(default_factory=dict)
    lines: list[tuple[int, str]] = field(default_factory=list)

    @property
    def description(self) -> FieldValue | None:
        return self.fields.get("description")

    @property
    def reference(self) -> FieldValue | None:
        return self.fields.get("reference")

    @property
    def inside_condition(self) -> bool:
        return "condition" in self.context

    @property
    def is_reportable_candidate(self) -> bool:
        return self.tag in REPORTABLE_TAGS and self.description is not None

    @property
    def marked_commented(self) -> bool:
        return self.commented_start or bool(self.description and self.description.commented)


@dataclass
class Control:
    block: Block
    fields: dict[str, str]
    control_id: str
    os: str
    os_version: str
    role: str
    benchmark_version: str
    level: str
    title: str
    reference_fields: dict[str, str]
    duplicate_reference_fields: set[str]

    @property
    def description(self) -> str:
        return self.block.description.value if self.block.description else ""

    @property
    def functional_key(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.control_id,
            self.os,
            self.os_version,
            self.benchmark_version,
            self.level,
            self.title,
        )


def add_issue(
    issues: list[Issue],
    file: str,
    line: int,
    code: str,
    detail: str,
    description: str = "",
    field_name: str = "",
    bad_value: str = "",
) -> None:
    issues.append(
        Issue(
            file=file,
            line=line,
            code=code,
            detail=detail,
            description=description,
            field_name=field_name,
            bad_value=bad_value,
        )
    )


def resolve_project_path(raw_path: str | Path) -> Path:
    path = Path(raw_path)
    if path.is_absolute() or path.exists():
        return path
    return PROJECT_ROOT / path


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def quoted_value_is_closed(raw: str, quote: str) -> bool:
    value = raw.strip()
    return len(value) >= 2 and value.endswith(quote)


def continuation_closes_field(line: str, quote: str, commented_field: bool) -> bool:
    value = strip_continuation_comment(line, commented_field).strip()
    if not value.endswith(quote):
        return False
    if len(value) >= 2 and value[-2] == "\\":
        return False
    return True


def strip_continuation_comment(line: str, commented_field: bool) -> str:
    if not commented_field:
        return line
    return re.sub(r"^\s*#\s?", "", line)


def tag_header_is_closed(line: str) -> bool:
    return ">" in line


def strip_tag_attr_value(raw_value: str) -> str:
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_tag_attrs(header_lines: list[str], tag: str) -> dict[str, str]:
    cleaned_header = " ".join(re.sub(r"^\s*#\s?", "", item).strip() for item in header_lines).strip()
    tag_match = re.match(rf"^<\s*/?\s*{re.escape(tag)}", cleaned_header, re.I)
    if not tag_match:
        return {}

    attr_text = cleaned_header[tag_match.end() :]
    if ">" in attr_text:
        attr_text = attr_text.split(">", 1)[0]

    attrs: dict[str, str] = {}
    for attr_match in TAG_ATTR_RE.finditer(attr_text):
        attrs[attr_match.group("key").lower()] = strip_tag_attr_value(attr_match.group("value"))
    return attrs


def strip_field_value(raw: str) -> tuple[str, str, bool]:
    value = raw.strip()
    quote = ""
    quote_closed = True
    if value and value[0] in {"'", '"'}:
        quote = value[0]
        quote_closed = quoted_value_is_closed(value, quote)
        value = value[1:]
        if quote_closed and value.endswith(quote):
            value = value[:-1]
    return value, quote, quote_closed


def line_is_commented(line: str) -> bool:
    return bool(re.match(r"^\s*#", line))


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
    open_field: tuple[int, str] | None = None
    pending_tag_header: tuple[str, int | None, list[str]] | None = None

    def append_to_active(line_number: int, raw_line: str) -> None:
        for active_index in active_block_indices:
            blocks[active_index].lines.append((line_number, raw_line))

    for idx, line in enumerate(lines, start=1):
        if open_field is not None:
            block_index, field_key = open_field
            if block_index in active_block_indices:
                append_to_active(idx, line)
                field_value = blocks[block_index].fields[field_key]
                continuation = strip_continuation_comment(line, field_value.commented)
                field_value.raw += "\n" + continuation
                field_value.end_line = idx
                if continuation_closes_field(line, field_value.quote, field_value.commented):
                    field_value.value, field_value.quote, field_value.quote_closed = strip_field_value(field_value.raw)
                    open_field = None
                continue
            open_field = None

        if pending_tag_header is not None:
            pending_tag, pending_block_index, header_lines = pending_tag_header
            append_to_active(idx, line)
            header_lines.append(line)
            if tag_header_is_closed(line):
                if pending_block_index is not None:
                    blocks[pending_block_index].tag_attrs = parse_tag_attrs(header_lines, pending_tag)
                pending_tag_header = None
            continue

        tag_match = TAG_RE.match(line)
        if tag_match and tag_match.group("close"):
            open_field = None
            tag = tag_match.group("tag").lower()
            append_to_active(idx, line)

            while stack:
                popped_tag, block_index = stack.pop()
                if block_index is not None and block_index in active_block_indices:
                    active_block_indices.remove(block_index)
                    blocks[block_index].end_line = idx
                if popped_tag == tag:
                    break
            continue

        if tag_match and not tag_match.group("close"):
            open_field = None
            tag = tag_match.group("tag").lower()
            if tag in STRUCTURAL_TAGS:
                block_index: int | None = None
                header_lines = [line]
                tag_attrs = parse_tag_attrs(header_lines, tag) if tag_header_is_closed(line) else {}
                if tag in REPORTABLE_TAGS:
                    block = Block(
                        tag=tag,
                        file=path,
                        start_line=idx,
                        context=tuple(item[0] for item in stack),
                        commented_start=bool(tag_match.group("comment")),
                        tag_attrs=tag_attrs,
                        lines=[(idx, line)],
                    )
                    blocks.append(block)
                    block_index = len(blocks) - 1
                    active_block_indices.append(block_index)

                for active_index in active_block_indices:
                    if active_index != block_index:
                        blocks[active_index].lines.append((idx, line))

                stack.append((tag, block_index))
                if not tag_header_is_closed(line):
                    pending_tag_header = (tag, block_index, header_lines)
                continue

        field_match = FIELD_RE.match(line)
        target_block_index: int | None = None
        if field_match:
            for _, block_index in reversed(stack):
                if block_index is not None:
                    target_block_index = block_index
                    break

        append_to_active(idx, line)

        if field_match and target_block_index is not None:
            block = blocks[target_block_index]
            key = field_match.group("key").lower()
            raw_value = field_match.group("value")
            value, quote, quote_closed = strip_field_value(raw_value)
            field_value = FieldValue(
                raw=raw_value,
                value=value,
                quote=quote,
                line=idx,
                end_line=idx,
                commented=bool(field_match.group("comment")),
                quote_closed=quote_closed,
            )
            block.fields[key] = field_value
            if quote and not quote_closed:
                open_field = (target_block_index, key)

    for block in blocks:
        for field_value in block.fields.values():
            if field_value.quote and not field_value.quote_closed:
                field_value.value, field_value.quote, field_value.quote_closed = strip_field_value(field_value.raw)

    return blocks


def match_family(path: Path, config: dict[str, Any]) -> dict[str, Any] | None:
    for family in config.get("families", []):
        if re.match(family["file_pattern"], path.name, re.I):
            return family
    return None


def configured_field_definitions(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    fields: dict[str, dict[str, Any]] = {}
    for group in config["reference"]["groups"].values():
        for field_def in group:
            fields[field_def["name"]] = field_def
    return fields


def required_reference_groups(control: Control, family: dict[str, Any] | None, config: dict[str, Any]) -> list[str]:
    groups = ["common"]
    configured_groups = family.get("reference_groups", []) if family else []
    if "windows_server" in configured_groups:
        groups.append("windows_server")

    server_roles = set(config["roles"]["windows_server_member_roles"] + config["roles"]["windows_server_dc_roles"])
    if control.role in server_roles and "windows_server" not in groups:
        groups.append("windows_server")
    return groups


def parse_reference_fields(reference: str) -> tuple[dict[str, str], set[str]]:
    fields: dict[str, str] = {}
    duplicates: set[str] = set()
    for part in reference.split(","):
        item = part.strip()
        if not item.startswith("CONTROL_") or "|" not in item:
            continue
        key, value = item.split("|", 1)
        if key in fields:
            duplicates.add(key)
        fields[key] = value
    return fields, duplicates


def parse_block_fields(block: Block, active_only: bool = False) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, field_value in block.fields.items():
        if active_only and field_value.commented:
            continue
        fields[key] = field_value.value
    return fields


def parse_domain_role_values(value_data: str) -> set[int]:
    return {int(item) for item in re.findall(r"\b\d+\b", value_data)}


def validate_tag_balance(path: Path, include_commented: bool, prefix: str) -> tuple[list[Issue], dict[str, int]]:
    issues: list[Issue] = []
    stats = {"tags": 0, "bad": 0}
    stack: list[tuple[str, int]] = []

    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if not include_commented and line_is_commented(line):
            continue

        tag_match = TAG_RE.match(line)
        if not tag_match:
            continue

        if not include_commented and tag_match.group("comment"):
            continue

        stats["tags"] += 1
        tag = tag_match.group("tag").lower()
        is_close = bool(tag_match.group("close"))

        if not is_close:
            stack.append((tag, line_number))
            continue

        if not stack:
            add_issue(issues, path.name, line_number, f"{prefix}_TAG_UNEXPECTED_CLOSE", f"Cierre sin apertura: {tag}")
            continue

        open_tag, open_line = stack.pop()
        if open_tag != tag:
            add_issue(
                issues,
                path.name,
                line_number,
                f"{prefix}_TAG_MISMATCH",
                f"Cierra {tag}, pero la apertura activa mas reciente es {open_tag} en linea {open_line}",
            )

    for open_tag, open_line in reversed(stack):
        add_issue(issues, path.name, open_line, f"{prefix}_TAG_UNCLOSED", f"Tag sin cierre: {open_tag}")

    stats["bad"] = len(issues)
    return issues, stats


def validate_commented_blocks(path: Path, blocks: list[Block]) -> tuple[list[Issue], dict[str, int]]:
    issues: list[Issue] = []
    stats = {"commented_blocks": 0, "bad": 0}

    for block in blocks:
        if not block.is_reportable_candidate or not block.marked_commented:
            continue

        stats["commented_blocks"] += 1
        for line_number, line in block.lines:
            if not line.strip():
                continue
            if not line_is_commented(line):
                add_issue(
                    issues,
                    path.name,
                    line_number,
                    "COMMENTED_BLOCK_PARTIAL",
                    "El control parece comentado, pero contiene lineas activas dentro del mismo bloque",
                    block.description.value if block.description else "",
                )
                break

    stats["bad"] = len(issues)
    return issues, stats


def validate_field_integrity(path: Path, blocks: list[Block]) -> tuple[list[Issue], dict[str, int]]:
    issues: list[Issue] = []
    stats = {"fields_checked": 0, "bad": 0}
    swallowed_tag_re = re.compile(r"</?(?:custom_item|item|report|if|condition|then|else)\b", re.I)

    for block in blocks:
        for key, field_value in block.fields.items():
            stats["fields_checked"] += 1
            if field_value.quote and not field_value.quote_closed:
                add_issue(
                    issues,
                    path.name,
                    field_value.line,
                    "FIELD_UNCLOSED_QUOTE",
                    f"El campo {key} empieza con comilla {field_value.quote} y no se cerro correctamente",
                    field_value.value,
                    field_name=key,
                    bad_value=field_value.raw,
                )

            if swallowed_tag_re.search(field_value.raw):
                add_issue(
                    issues,
                    path.name,
                    field_value.line,
                    "FIELD_SWALLOWED_TENABLE_TAG",
                    f"El campo {key} contiene etiquetas Tenable; probable cierre multilínea mal interpretado",
                    field_value.value,
                    field_name=key,
                    bad_value=field_value.raw,
                )

    stats["bad"] = len(issues)
    return issues, stats


def validate_description(
    issues: list[Issue],
    file_name: str,
    field_value: FieldValue,
    config: dict[str, Any],
    require_double_quote: bool,
    prefix: str = "DESCRIPTION",
) -> dict[str, str] | None:
    value = field_value.value
    raw_value = field_value.raw

    if require_double_quote and field_value.quote != '"':
        add_issue(
            issues,
            file_name,
            field_value.line,
            f"{prefix}_NOT_DOUBLE_QUOTED",
            'El description reportable debe delimitarse con comillas dobles exteriores (")',
            value,
            field_name="description",
            bad_value=raw_value,
        )

    if field_value.quote and not field_value.quote_closed:
        add_issue(
            issues,
            file_name,
            field_value.line,
            f"{prefix}_UNCLOSED_QUOTE",
            f"El campo empieza con comilla {field_value.quote} pero no se encontro cierre antes de terminar el parseo del valor",
            value,
            field_name="description",
            bad_value=raw_value,
        )

    if re.search(r"\\['\"]", value) or re.search(r"\\['\"]", raw_value):
        add_issue(
            issues,
            file_name,
            field_value.line,
            f"{prefix}_ESCAPED_QUOTE",
            "El description contiene comillas escapadas con backslash",
            value,
            field_name="description",
            bad_value=value,
        )

    if field_value.quote == "'" and "'" in value:
        add_issue(
            issues,
            file_name,
            field_value.line,
            f"{prefix}_SINGLE_QUOTED_WITH_APOSTROPHE",
            "El description esta delimitado con comilla simple y contiene apostrofes",
            value,
            field_name="description",
            bad_value=value,
        )

    if re.search(r" {2,}", value):
        add_issue(
            issues,
            file_name,
            field_value.line,
            f"{prefix}_CONSECUTIVE_SPACES",
            "El description contiene espacios consecutivos",
            value,
            field_name="description",
            bad_value=value,
        )

    if re.search(r"\[IG\d+\]", value):
        add_issue(
            issues,
            file_name,
            field_value.line,
            f"{prefix}_IG_IN_DESCRIPTION",
            "IG no debe estar en description",
            value,
            field_name="description",
            bad_value=value,
        )

    if re.search(r"\]\[L\d+\]\s+\([Ll]\d+\)", value):
        add_issue(
            issues,
            file_name,
            field_value.line,
            f"{prefix}_DUPLICATE_LEVEL",
            "El nivel no debe duplicarse como [Lx] (Lx)",
            value,
            field_name="description",
            bad_value=value,
        )

    if re.search(r"CONTROL_|CUSTOMER|MS_ONLY|DC_ONLY|INTERNAL_VERSION", value):
        add_issue(
            issues,
            file_name,
            field_value.line,
            f"{prefix}_REFERENCE_FIELD_IN_DESCRIPTION",
            "Campos de reference no deben aparecer en description",
            value,
            field_name="description",
            bad_value=value,
        )

    match = DESCRIPTION_RE.match(value)
    if not match:
        separator_match = re.search(r"\]\[L\d+\](?P<sep>\s+)", value)
        if separator_match and separator_match.group("sep") != " ":
            detail = "Debe haber exactamente un espacio entre [LEVEL] y el titulo"
        else:
            detail = "No sigue la estructura [control_id][OS][OS_VERSION][ROLE][BENCHMARK_VERSION][LEVEL] titulo"
        add_issue(
            issues,
            file_name,
            field_value.line,
            f"{prefix}_BAD_NAMING",
            detail,
            value,
            field_name="description",
            bad_value=value,
        )
        return None

    fields = match.groupdict()
    allowed = config["naming"]["allowed_values"]
    for field_name in ("os", "os_version", "role", "benchmark_version", "level"):
        if fields[field_name] not in allowed[field_name]:
            add_issue(
                issues,
                file_name,
                field_value.line,
                f"{prefix}_VALUE_NOT_ALLOWED",
                f"{field_name} no permitido por validator_config.json: {fields[field_name]}",
                value,
                field_name=f"description.{field_name}",
                bad_value=fields[field_name],
            )

    if fields["title"] != fields["title"].strip():
        add_issue(
            issues,
            file_name,
            field_value.line,
            f"{prefix}_TITLE_TRIM",
            "El titulo tiene espacios al inicio o final",
            value,
            field_name="description.title",
            bad_value=fields["title"],
        )

    return fields


def validate_reference_value(
    issues: list[Issue],
    file_name: str,
    line: int,
    field_name: str,
    actual: str,
    field_def: dict[str, Any],
    description: str,
) -> None:
    value_type = field_def["type"]

    if value_type == "boolean":
        if actual not in {"true", "false"}:
            add_issue(
                issues,
                file_name,
                line,
                "REFERENCE_FIELD_BAD_VALUE",
                f"{field_name} debe ser booleano estricto true/false en minusculas; encontrado: {actual}",
                description,
                field_name=field_name,
                bad_value=actual,
            )
        return

    if value_type == "integer":
        if not re.fullmatch(r"\d+", actual):
            add_issue(
                issues,
                file_name,
                line,
                "REFERENCE_FIELD_BAD_VALUE",
                f"{field_name} debe ser entero no negativo; encontrado: {actual}",
                description,
                field_name=field_name,
                bad_value=actual,
            )
            return
        minimum = field_def.get("min")
        if minimum is not None and int(actual) < int(minimum):
            add_issue(
                issues,
                file_name,
                line,
                "REFERENCE_FIELD_BAD_VALUE",
                f"{field_name} debe ser >= {minimum}; encontrado: {actual}",
                description,
                field_name=field_name,
                bad_value=actual,
            )
        return

    if value_type == "enum":
        allowed_values = set(field_def["allowed_values"])
        if actual not in allowed_values:
            allowed_text = ", ".join(sorted(allowed_values))
            add_issue(
                issues,
                file_name,
                line,
                "REFERENCE_FIELD_BAD_VALUE",
                f"{field_name} debe ser uno de [{allowed_text}]; encontrado: {actual}",
                description,
                field_name=field_name,
                bad_value=actual,
            )
        return

    add_issue(
        issues,
        file_name,
        line,
        "REFERENCE_FIELD_UNKNOWN_VALIDATOR_TYPE",
        f"Tipo de validador no soportado para {field_name}: {value_type}",
        description,
        field_name=field_name,
        bad_value=value_type,
    )


def validate_reference(
    issues: list[Issue],
    control: Control,
    family: dict[str, Any] | None,
    config: dict[str, Any],
) -> None:
    block = control.block
    file_name = block.file.name
    description = control.description

    if block.reference is None:
        add_issue(
            issues,
            file_name,
            block.start_line,
            "REFERENCE_MISSING",
            "Control reportable sin campo reference",
            description,
            field_name="reference",
            bad_value="<missing>",
        )
        return

    if block.reference.quote != '"':
        add_issue(
            issues,
            file_name,
            block.reference.line,
            "REFERENCE_NOT_DOUBLE_QUOTED",
            'El reference de controles reportables debe delimitarse con comillas dobles exteriores (")',
            description,
            field_name="reference",
            bad_value=block.reference.raw,
        )

    if block.reference.quote and not block.reference.quote_closed:
        add_issue(
            issues,
            file_name,
            block.reference.line,
            "REFERENCE_UNCLOSED_QUOTE",
            "El reference empieza con comilla pero no se encontro cierre antes de terminar el parseo del valor",
            description,
            field_name="reference",
            bad_value=block.reference.raw,
        )

    all_field_defs = configured_field_definitions(config)
    for duplicate in sorted(control.duplicate_reference_fields):
        add_issue(
            issues,
            file_name,
            block.reference.line,
            "REFERENCE_FIELD_DUPLICATE",
            f"Campo CONTROL_* duplicado: {duplicate}",
            description,
            field_name=duplicate,
            bad_value=control.reference_fields.get(duplicate, ""),
        )

    if not config["reference"].get("allow_unknown_control_fields", False):
        for field_name in sorted(control.reference_fields):
            if field_name not in all_field_defs:
                add_issue(
                    issues,
                    file_name,
                    block.reference.line,
                    "REFERENCE_UNKNOWN_CONTROL_FIELD",
                    f"Campo CONTROL_* no definido en validator_config.json: {field_name}",
                    description,
                    field_name=field_name,
                    bad_value=control.reference_fields[field_name],
                )

    for group_name in required_reference_groups(control, family, config):
        for field_def in config["reference"]["groups"][group_name]:
            field_name = field_def["name"]
            actual = control.reference_fields.get(field_name)
            if actual is None:
                add_issue(
                    issues,
                    file_name,
                    block.reference.line,
                    "REFERENCE_FIELD_MISSING",
                    f"Falta campo obligatorio: {field_name}",
                    description,
                    field_name=field_name,
                    bad_value="<missing>",
                )
                continue
            validate_reference_value(issues, file_name, block.reference.line, field_name, actual, field_def, description)

    forbidden_fields = set(family.get("forbidden_reference_fields", []) if family else [])
    for field_name in sorted(forbidden_fields):
        if field_name in control.reference_fields:
            add_issue(
                issues,
                file_name,
                block.reference.line,
                "REFERENCE_FIELD_FORBIDDEN",
                f"Campo no permitido para esta familia: {field_name}",
                description,
                field_name=field_name,
                bad_value=control.reference_fields[field_name],
            )

    customer = control.reference_fields.get("CONTROL_CUSTOMER")
    cis = control.reference_fields.get("CONTROL_CIS")
    if customer is not None and cis is not None:
        allowed_pairs = {tuple(pair) for pair in config["reference"].get("allowed_customer_cis_pairs", [])}
        if (customer, cis) not in allowed_pairs:
            add_issue(
                issues,
                file_name,
                block.reference.line,
                "REFERENCE_CUSTOMER_CIS_PAIR",
                f"Combinacion CONTROL_CUSTOMER/CONTROL_CIS no permitida: {customer}/{cis}",
                description,
                field_name="CONTROL_CUSTOMER/CONTROL_CIS",
                bad_value=f"{customer}/{cis}",
            )


def build_control(block: Block) -> Control | None:
    if block.description is None:
        return None

    match = DESCRIPTION_RE.match(block.description.value)
    if not match:
        return None

    reference = block.reference.value if block.reference else ""
    reference_fields, duplicates = parse_reference_fields(reference)
    fields = match.groupdict()
    return Control(
        block=block,
        fields=fields,
        control_id=fields["control_id"],
        os=fields["os"],
        os_version=fields["os_version"],
        role=fields["role"],
        benchmark_version=fields["benchmark_version"],
        level=fields["level"],
        title=fields["title"],
        reference_fields=reference_fields,
        duplicate_reference_fields=duplicates,
    )


def build_control_for_reference(block: Block, fields: dict[str, str] | None) -> Control:
    control_fields = fields or {
        "control_id": "0",
        "os": "N/A",
        "os_version": "N/A",
        "role": "N/A",
        "benchmark_version": "v0.0.0",
        "level": "L1",
        "title": block.description.value if block.description else "",
    }
    reference = block.reference.value if block.reference else ""
    reference_fields, duplicates = parse_reference_fields(reference)
    return Control(
        block=block,
        fields=control_fields,
        control_id=control_fields["control_id"],
        os=control_fields["os"],
        os_version=control_fields["os_version"],
        role=control_fields["role"],
        benchmark_version=control_fields["benchmark_version"],
        level=control_fields["level"],
        title=control_fields["title"],
        reference_fields=reference_fields,
        duplicate_reference_fields=duplicates,
    )


def validate_family_metadata(
    issues: list[Issue],
    control: Control,
    family: dict[str, Any] | None,
) -> None:
    if family is None:
        return

    expected = family.get("expected", {})
    description = control.description
    file_name = control.block.file.name
    line = control.block.description.line if control.block.description else control.block.start_line

    for field_name in ("os", "os_version", "benchmark_version", "level"):
        expected_value = expected.get(field_name)
        if expected_value and control.fields[field_name] != expected_value:
            add_issue(
                issues,
                file_name,
                line,
                "SEMANTIC_FIELD_VALUE",
                f"{field_name} esperado por familia {family['name']}: {expected_value}; encontrado: {control.fields[field_name]}",
                description,
                field_name=f"description.{field_name}",
                bad_value=control.fields[field_name],
            )

    expected_roles = expected.get("roles", [])
    if expected_roles and control.role not in expected_roles:
        add_issue(
            issues,
            file_name,
            line,
            "SEMANTIC_ROLE",
            f"ROLE no esperado para familia {family['name']}: {control.role}",
            description,
            field_name="description.role",
            bad_value=control.role,
        )


def validate_windows_server_flag_semantics(
    controls: list[Control],
    config: dict[str, Any],
) -> tuple[list[Issue], dict[str, int]]:
    issues: list[Issue] = []
    stats = {"windows_flags_checked": 0, "bad": 0}
    roles_by_key: dict[tuple[str, str, str, str, str, str], set[str]] = {}

    member_roles = set(config["roles"]["windows_server_member_roles"])
    dc_roles = set(config["roles"]["windows_server_dc_roles"])
    neutral_roles = set(config["roles"]["neutral_roles"])
    server_roles = member_roles | dc_roles | neutral_roles

    server_controls = [control for control in controls if control.role in server_roles and "CONTROL_MS_ONLY" in control.reference_fields]
    for control in server_controls:
        roles_by_key.setdefault(control.functional_key, set()).add(control.role)

    for control in server_controls:
        stats["windows_flags_checked"] += 1
        peer_roles = roles_by_key.get(control.functional_key, set())
        expected_ms_only = None
        expected_dc_only = None

        if control.role in neutral_roles:
            expected_ms_only = "false"
            expected_dc_only = "false"
        elif control.role in member_roles:
            expected_ms_only = "false" if peer_roles & dc_roles else "true"
            expected_dc_only = "false"
        elif control.role in dc_roles:
            expected_ms_only = "false"
            expected_dc_only = "false" if peer_roles & member_roles else "true"

        reference_line = control.block.reference.line if control.block.reference else control.block.start_line
        if expected_ms_only is not None:
            actual = control.reference_fields.get("CONTROL_MS_ONLY")
            if actual is not None and actual != expected_ms_only:
                add_issue(
                    issues,
                    control.block.file.name,
                    reference_line,
                    "REFERENCE_MS_ONLY_SEMANTICS",
                    f"CONTROL_MS_ONLY esperado: {expected_ms_only}; encontrado: {actual}",
                    control.description,
                    field_name="CONTROL_MS_ONLY",
                    bad_value=actual,
                )

        if expected_dc_only is not None:
            actual = control.reference_fields.get("CONTROL_DC_ONLY")
            if actual is not None and actual != expected_dc_only:
                add_issue(
                    issues,
                    control.block.file.name,
                    reference_line,
                    "REFERENCE_DC_ONLY_SEMANTICS",
                    f"CONTROL_DC_ONLY esperado: {expected_dc_only}; encontrado: {actual}",
                    control.description,
                    field_name="CONTROL_DC_ONLY",
                    bad_value=actual,
                )

    stats["bad"] = len(issues)
    return issues, stats


def find_active_domain_role_conditions(blocks: list[Block]) -> list[set[int]]:
    detected: list[set[int]] = []
    for block in blocks:
        if block.tag not in {"custom_item", "item"} or not block.inside_condition or block.marked_commented:
            continue

        fields = parse_block_fields(block, active_only=True)
        if fields.get("type", "").upper() != "WMI_POLICY":
            continue

        request = fields.get("wmi_request", "")
        attribute = fields.get("wmi_attribute", "")
        key = fields.get("wmi_key", "")
        if not re.search(r"select\s+DomainRole\s+from\s+Win32_ComputerSystem", request, re.I):
            continue
        if attribute.lower() != "domainrole" and key.lower() != "domainrole":
            continue

        values = parse_domain_role_values(fields.get("value_data", ""))
        if values:
            detected.append(values)
    return detected


def validate_unified_role_detection(
    path: Path,
    blocks: list[Block],
    family: dict[str, Any] | None,
) -> tuple[list[Issue], dict[str, int]]:
    issues: list[Issue] = []
    stats = {"role_detection_checked": 0, "bad": 0}
    if not family or not family.get("requires_unified_role_detection"):
        return issues, stats

    detected_sets = find_active_domain_role_conditions(blocks)
    for requirement in family.get("role_detection", []):
        stats["role_detection_checked"] += 1
        expected = set(requirement["domain_role_values"])
        if expected not in detected_sets:
            expected_text = " || ".join(str(item) for item in sorted(expected))
            add_issue(
                issues,
                path.name,
                1,
                "WINDOWS_SERVER_ROLE_DETECTION_MISSING",
                f"Falta condicion activa DomainRole para {requirement['name']}: {expected_text}",
                field_name="DomainRole",
                bad_value="<missing>",
            )

    stats["bad"] = len(issues)
    return issues, stats


def validate_reportable_blocks(
    path: Path,
    blocks: list[Block],
    family: dict[str, Any] | None,
    config: dict[str, Any],
    documented_aux: set[tuple[str, int]],
) -> tuple[list[Issue], list[Control], dict[str, int]]:
    issues: list[Issue] = []
    controls: list[Control] = []
    stats = {"blocks": len(blocks), "reportable_candidates": 0, "reportable": 0, "auxiliary": 0, "bad": 0}

    for block in blocks:
        if block.description is None:
            continue

        documented = (path.name, block.description.line) in documented_aux
        is_auxiliary = block.inside_condition or documented

        if is_auxiliary:
            stats["auxiliary"] += 1
            if DESCRIPTION_RE.match(block.description.value):
                validate_description(issues, path.name, block.description, config, require_double_quote=True)
            continue

        stats["reportable_candidates"] += 1
        fields = validate_description(issues, path.name, block.description, config, require_double_quote=True)
        control = build_control_for_reference(block, fields)
        if fields is None:
            add_issue(
                issues,
                path.name,
                block.description.line,
                "REPORTABLE_DESCRIPTION_WITHOUT_NAMING",
                "Bloque terminal con description sin naming convention y no documentado como auxiliar",
                block.description.value,
                field_name="description",
                bad_value=block.description.value,
            )
            validate_reference(issues, control, family, config)
            continue

        stats["reportable"] += 1
        validate_family_metadata(issues, control, family)
        validate_reference(issues, control, family, config)
        controls.append(control)

    stats["bad"] = len(issues)
    return issues, controls, stats


def validate_one_audit(
    path: Path,
    config: dict[str, Any],
    documented_aux: set[tuple[str, int]],
) -> tuple[list[Issue], dict[str, int]]:
    family = match_family(path, config)
    blocks = iter_audit_blocks(path)

    issues: list[Issue] = []
    reportable_issues, controls, stats = validate_reportable_blocks(path, blocks, family, config, documented_aux)
    active_tag_issues, active_tag_stats = validate_tag_balance(path, include_commented=False, prefix="ACTIVE")
    all_tag_issues, all_tag_stats = validate_tag_balance(path, include_commented=True, prefix="ALL")
    comment_issues, comment_stats = validate_commented_blocks(path, blocks)
    field_issues, field_stats = validate_field_integrity(path, blocks)
    role_issues, role_stats = validate_unified_role_detection(path, blocks, family)
    flag_issues, flag_stats = validate_windows_server_flag_semantics(controls, config)

    for issue_group in (
        reportable_issues,
        active_tag_issues,
        all_tag_issues,
        comment_issues,
        field_issues,
        role_issues,
        flag_issues,
    ):
        issues.extend(issue_group)

    stats.update(
        {
            "active_tags": active_tag_stats["tags"],
            "all_tags": all_tag_stats["tags"],
            "commented_blocks": comment_stats["commented_blocks"],
            "fields_checked": field_stats["fields_checked"],
            "role_detection_checked": role_stats["role_detection_checked"],
            "windows_flags_checked": flag_stats["windows_flags_checked"],
            "bad": len(issues),
        }
    )
    return issues, stats


def validate_summary_csv(path: Path, config: dict[str, Any]) -> tuple[list[Issue], dict[str, int]]:
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

            field_value = FieldValue(
                raw=name,
                value=name,
                quote="",
                line=row_index,
                end_line=row_index,
                commented=False,
            )
            if validate_description(issues, path.name, field_value, config, require_double_quote=False, prefix="SUMMARY_DESCRIPTION"):
                stats["named"] += 1

    stats["bad"] = len(issues)
    return issues, stats


def collect_audit_files(args: argparse.Namespace, config: dict[str, Any]) -> list[Path]:
    audit_files = [resolve_project_path(item) for item in args.audit]
    if audit_files:
        return audit_files

    audit_dir = resolve_project_path(args.audit_dir or config["defaults"]["audit_dir"])
    if not audit_dir.exists():
        raise FileNotFoundError(f"No existe la carpeta de audits: {audit_dir}")

    files = sorted(audit_dir.glob("*.audit"))
    if not files:
        raise FileNotFoundError(f"No se encontraron ficheros .audit en: {audit_dir}")
    return files


def write_report(report_path: Path, issues: list[Issue], stats: dict[str, dict[str, int]]) -> None:
    payload = {
        "stats": stats,
        "issue_count": len(issues),
        "issues": [asdict(issue) for issue in issues],
    }
    report_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def issue_category(code: str) -> str:
    if code.startswith(("DESCRIPTION", "REPORTABLE_DESCRIPTION", "SEMANTIC_", "SUMMARY_DESCRIPTION")):
        return "Description / naming"
    if code.startswith("REFERENCE"):
        return "Reference CONTROL_*"
    if code.startswith("WINDOWS_SERVER_ROLE_DETECTION"):
        return "Windows Server role detection"
    if code.startswith(("ACTIVE_TAG", "ALL_TAG", "COMMENTED_BLOCK", "FIELD_")):
        return "Estructura Tenable"
    if code.startswith("SUMMARY"):
        return "Summary CSV"
    return "Otros"


def aggregate_stats(stats_by_file: dict[str, dict[str, int]]) -> dict[str, int]:
    totals = {
        "files": len(stats_by_file),
        "reportable_candidates": 0,
        "reportable": 0,
        "auxiliary": 0,
        "rows": 0,
        "role_detection_checked": 0,
        "bad": 0,
    }
    for stats in stats_by_file.values():
        for key in ("reportable_candidates", "reportable", "auxiliary", "rows", "role_detection_checked", "bad"):
            totals[key] += stats.get(key, 0)
    return totals


def print_details(stats_by_file: dict[str, dict[str, int]]) -> None:
    print("\nDetalle tecnico:")
    for name, stats in stats_by_file.items():
        stat_text = ", ".join(f"{key}={value}" for key, value in stats.items())
        print(f"- {name}: {stat_text}")


def display_field_name(issue: Issue) -> str:
    if issue.field_name:
        return issue.field_name
    category = issue_category(issue.code)
    if category == "Description / naming":
        return "description"
    if category == "Reference CONTROL_*":
        return "reference"
    if category == "Windows Server role detection":
        return "DomainRole"
    if category == "Estructura Tenable":
        return "estructura"
    return "N/A"


def display_bad_value(issue: Issue) -> str:
    if issue.bad_value:
        return issue.bad_value

    found_match = re.search(r"encontrado:\s*(?P<value>.+)$", issue.detail)
    if found_match:
        return found_match.group("value")

    not_allowed_match = re.search(r"no permitida:\s*(?P<value>.+)$", issue.detail)
    if not_allowed_match:
        return not_allowed_match.group("value")

    if issue.code.endswith("_MISSING"):
        return "<missing>"

    if issue_category(issue.code) == "Description / naming" and issue.description:
        return issue.description

    return "N/A"


def print_human_report(issues: list[Issue], stats_by_file: dict[str, dict[str, int]], details: bool) -> None:
    totals = aggregate_stats(stats_by_file)
    grouped_counts: dict[str, int] = {}
    for issue in issues:
        category = issue_category(issue.code)
        grouped_counts[category] = grouped_counts.get(category, 0) + 1

    if issues:
        print("VALIDATOR FAIL")
        print(f"Audits/entradas revisadas: {totals['files']}")
        print(f"Controles reportables detectados: {totals['reportable_candidates']}")
        print(f"Incidencias totales: {len(issues)}")
        print("")
        for category in (
            "Description / naming",
            "Reference CONTROL_*",
            "Windows Server role detection",
            "Estructura Tenable",
            "Summary CSV",
            "Otros",
        ):
            if category in grouped_counts:
                print(f"- {category}: {grouped_counts[category]} incidencia(s)")

        issues_by_file: dict[str, list[Issue]] = {}
        for issue in issues:
            issues_by_file.setdefault(issue.file, []).append(issue)

        print("\nIncidencias por fichero:")
        ordered_files = [name for name in stats_by_file if name in issues_by_file]
        ordered_files.extend(sorted(name for name in issues_by_file if name not in stats_by_file))

        for file_name in ordered_files:
            file_issues = sorted(issues_by_file[file_name], key=lambda item: (item.line, issue_category(item.code), item.code))
            print(f"\n{file_name}")
            print("-" * len(file_name))

            for issue in file_issues:
                print("")
                print(f"  Linea {issue.line} [{issue_category(issue.code)}]")
                print(f"  {issue.detail}")
                print(f"  Campo con error: {display_field_name(issue)}")
                print(f"  Valor erroneo: {display_bad_value(issue)}")
                print(f"  Codigo: {issue.code}")
                if issue.description:
                    print(f"  Control: {issue.description}")
    else:
        print("VALIDATOR OK")
        print(f"Audits/entradas revisadas: {totals['files']}")
        print(f"Controles reportables detectados: {totals['reportable_candidates']}")
        print("- Description / naming: OK")
        print("- Reference CONTROL_*: OK")
        print("- Estructura Tenable: OK")
        if totals["role_detection_checked"]:
            print(f"- Windows Server role detection: OK ({totals['role_detection_checked']} comprobaciones)")
        else:
            print("- Windows Server role detection: N/A")
        print("\nUsa --details para ver contadores tecnicos por fichero.")

    if details:
        print_details(stats_by_file)


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validator canonico para ficheros .audit del proyecto.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Fichero JSON de configuracion del validator.")
    parser.add_argument("--audit-dir", default="", help="Directorio de .audit a validar.")
    parser.add_argument("--audit", action="append", default=[], help="Fichero .audit concreto. Se puede repetir.")
    parser.add_argument("--auxiliary-doc", default="", help="Documento Markdown con auxiliares permitidos.")
    parser.add_argument("--summary", action="append", default=[], help="CSV summary de Tenable a validar. Se puede repetir.")
    parser.add_argument("--json-report", default="", help="Ruta opcional para escribir un reporte JSON.")
    parser.add_argument("--details", action="store_true", help="Muestra contadores tecnicos por fichero.")
    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = parse_args(argv)
    config_path = resolve_project_path(args.config)
    config = load_config(config_path)
    auxiliary_doc = resolve_project_path(args.auxiliary_doc or config["defaults"]["auxiliary_doc"])
    documented_aux = parse_auxiliary_doc(auxiliary_doc)

    try:
        audit_files = collect_audit_files(args, config)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    all_issues: list[Issue] = []
    all_stats: dict[str, dict[str, int]] = {}

    for audit_file in audit_files:
        issues, stats = validate_one_audit(audit_file, config, documented_aux)
        all_issues.extend(issues)
        all_stats[audit_file.name] = stats

    for summary_file in args.summary:
        summary_path = resolve_project_path(summary_file)
        issues, stats = validate_summary_csv(summary_path, config)
        all_issues.extend(issues)
        all_stats[summary_path.name] = stats

    if args.json_report:
        write_report(resolve_project_path(args.json_report), all_issues, all_stats)
        print(f"Reporte JSON: {args.json_report}\n")

    print_human_report(all_issues, all_stats, args.details)
    return 1 if all_issues else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
