"""
result_parser.py
-----------------
Component 1: Result Parser Module

Reads the raw JSON output produced by SAST tools (Bandit, SonarQube) and
extracts the key fields needed for evaluation: file path, line number,
rule/test ID, severity, message, and (when present) a CWE identifier.

This module deliberately does NOT try to unify the two tools' formats --
that job belongs to `normalizer.py`. Each `parse_*` function here simply
turns one tool's raw JSON into a list of plain dicts using that tool's own
native field names, so the parsing step and the normalisation step can be
tested/debugged independently.
"""

import json
import os


class ParseError(Exception):
    """Raised when a results file cannot be read or is not valid JSON."""
    pass


def _load_json(path):
    if not os.path.isfile(path):
        raise ParseError(f"File not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ParseError(f"Invalid JSON in {path}: {e}")


def parse_bandit(path):
    """
    Parse a Bandit JSON report (`bandit -f json -o report.json ...`).

    Returns a list of dicts, one per Bandit result, with the raw fields:
        file, line, end_line, test_id, test_name, severity,
        confidence, message, cwe_id (int or None)
    """
    data = _load_json(path)
    results = data.get("results", [])
    if not isinstance(results, list):
        raise ParseError("Unexpected Bandit JSON structure: 'results' is not a list")

    parsed = []
    for item in results:
        line_range = item.get("line_range") or []
        end_line = line_range[-1] if line_range else item.get("line_number")

        # Newer Bandit versions (>=1.7.5) embed CWE info directly:
        #   "issue_cwe": {"id": 259, "link": "https://cwe.mitre.org/..."}
        cwe_id = None
        cwe_block = item.get("issue_cwe")
        if isinstance(cwe_block, dict) and cwe_block.get("id") is not None:
            cwe_id = cwe_block.get("id")

        parsed.append({
            "file": item.get("filename"),
            "line": item.get("line_number"),
            "end_line": end_line,
            "test_id": item.get("test_id"),
            "test_name": item.get("test_name"),
            "severity": item.get("issue_severity"),
            "confidence": item.get("issue_confidence"),
            "message": item.get("issue_text"),
            "cwe_id": cwe_id,
        })
    return parsed


def parse_sonarqube(path):
    """
    Parse a SonarQube/SonarCloud issues export JSON, i.e. the payload shape
    returned by the `/api/issues/search` endpoint (a dict with an "issues"
    list), OR a plain list of issue dicts in that same shape.

    Returns a list of dicts, one per SonarQube issue, with the raw fields:
        file, line, end_line, rule, severity, type, message, cwe_id (None;
        SonarQube's issue payload does not include CWE directly -- see
        normalizer.py for how CWE is attached via a rule->CWE lookup table).
    """
    data = _load_json(path)
    issues = data["issues"] if isinstance(data, dict) and "issues" in data else data
    if not isinstance(issues, list):
        raise ParseError("Unexpected SonarQube JSON structure: expected a list of issues "
                          "or a dict containing an 'issues' list")

    parsed = []
    for item in issues:
        # SonarQube's "component" is usually "<projectKey>:<path/to/file.py>"
        component = item.get("component", "") or ""
        file_path = component.split(":", 1)[1] if ":" in component else component

        text_range = item.get("textRange") or {}
        line = item.get("line", text_range.get("startLine"))
        end_line = text_range.get("endLine", line)

        parsed.append({
            "file": file_path,
            "line": line,
            "end_line": end_line,
            "rule": item.get("rule"),
            "severity": item.get("severity"),
            "type": item.get("type"),
            "message": item.get("message"),
            "cwe_id": None,  # attached later in normalizer.py via a rule->CWE map
        })
    return parsed


# Convenience dispatch table used by the GUI / higher-level callers.
PARSERS = {
    "bandit": parse_bandit,
    "sonarqube": parse_sonarqube,
}


def parse(tool, path):
    """Dispatch to the correct parser by tool name ('bandit' | 'sonarqube')."""
    tool_key = tool.strip().lower()
    if tool_key not in PARSERS:
        raise ParseError(f"Unknown tool '{tool}'. Supported: {list(PARSERS)}")
    return PARSERS[tool_key](path)
