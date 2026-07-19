"""
normalizer.py
-------------
Component 2: Output Normalisation Module

Maps the tool-specific dicts produced by `result_parser.py` into a single,
unified schema (`Finding`) so that Bandit and SonarQube results can be
compared on an apples-to-apples basis by the rest of the toolkit.

Unified schema (one Finding per detected issue):
    tool        : "Bandit" | "SonarQube"
    file        : normalised, forward-slash relative file path
    line        : int  (primary line number)
    end_line    : int  (best-effort; falls back to `line` if unknown)
    rule_id     : the tool's own rule/check identifier (e.g. "B608", "python:S2077")
    cwe         : "CWE-89" style string, or "CWE-UNKNOWN" if it could not be resolved
    severity    : normalised to {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    issue_type  : "VULNERABILITY" | "BUG" | "CODE_SMELL" | ... (Bandit findings
                  are always reported as "VULNERABILITY" -- Bandit is a
                  security-only tool by design and has no equivalent concept)
    message     : original human-readable finding text

Why `issue_type` matters (SonarQube-specific):
SonarQube's default quality profile reports far more than security issues --
BUG and CODE_SMELL (code-quality/maintainability) issues make up the bulk of
a typical scan. Comparing an *unfiltered* SonarQube export against a
security-only ground truth (and against Bandit, a security-only tool) is not
an apples-to-apples comparison: every non-VULNERABILITY issue is guaranteed
to be a False Positive. `normalise_sonarqube(..., include_types=...)` lets
you filter this at the toolkit level (Option 2); `summarize_issue_types()`
lets you see the breakdown before deciding; and the README documents how to
filter at the SonarQube export/API level instead (Option 1).
"""

import json
import os
from collections import Counter
from dataclasses import dataclass, asdict

from result_parser import parse_bandit, parse_sonarqube

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_BANDIT_MAP = os.path.join(_HERE, "config", "bandit_cwe_map.json")
_DEFAULT_SONAR_MAP = os.path.join(_HERE, "config", "sonar_cwe_map.json")

# SonarQube issue types, for reference (used by the GUI's type-filter checkbox):
#   VULNERABILITY   -- a security-relevant defect (the only type directly
#                       comparable to what Bandit reports)
#   SECURITY_HOTSPOT-- flagged code that *may* be a vulnerability and needs
#                       manual review; NOT returned by /api/issues/search --
#                       requires the separate /api/hotspots/search endpoint
#                       (different JSON shape; not parsed by this toolkit yet)
#   BUG             -- a functional/reliability defect, not security-related
#   CODE_SMELL      -- a maintainability issue, not security-related
SONARQUBE_ISSUE_TYPES = ("VULNERABILITY", "BUG", "CODE_SMELL", "SECURITY_HOTSPOT")


@dataclass
class Finding:
    tool: str
    file: str
    line: int
    end_line: int
    rule_id: str
    cwe: str
    severity: str
    issue_type: str
    message: str

    def as_dict(self):
        return asdict(self)


def _load_cwe_map(path):
    if not path or not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def normalise_path(path):
    """Turn any path into a clean, forward-slash relative-looking path so
    that Windows/Linux/SonarQube-component-key differences don't break
    matching later on."""
    if not path:
        return ""
    p = path.replace("\\", "/")
    # Strip a leading "./" and any drive letter / leading slash noise.
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


_BANDIT_SEVERITY_MAP = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

_SONAR_SEVERITY_MAP = {
    "BLOCKER": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "MAJOR": "HIGH",
    "MINOR": "MEDIUM",
    "INFO": "LOW",
}


def normalise_bandit(raw_results, cwe_map_path=_DEFAULT_BANDIT_MAP):
    """Convert parse_bandit() output into a list of unified Finding objects.
    Bandit only ever reports security issues, so issue_type is always
    "VULNERABILITY" -- there is no filtering equivalent to SonarQube's."""
    cwe_map = _load_cwe_map(cwe_map_path)
    findings = []
    for item in raw_results:
        cwe_id = item.get("cwe_id")
        if cwe_id is not None:
            cwe = f"CWE-{cwe_id}"
        else:
            cwe = cwe_map.get(item.get("test_id"), "CWE-UNKNOWN")

        findings.append(Finding(
            tool="Bandit",
            file=normalise_path(item.get("file")),
            line=int(item.get("line") or 0),
            end_line=int(item.get("end_line") or item.get("line") or 0),
            rule_id=item.get("test_id") or "",
            cwe=cwe,
            severity=_BANDIT_SEVERITY_MAP.get((item.get("severity") or "").upper(), "MEDIUM"),
            issue_type="VULNERABILITY",
            message=item.get("message") or "",
        ))
    return findings


def summarize_issue_types(raw_issues):
    """Return a Counter of SonarQube issue 'type' values in a raw parsed
    list (as produced by result_parser.parse_sonarqube). Use this to see
    the VULNERABILITY / BUG / CODE_SMELL breakdown before deciding whether
    to filter."""
    return Counter((item.get("type") or "UNKNOWN").upper() for item in raw_issues)


def normalise_sonarqube(raw_issues, cwe_map_path=_DEFAULT_SONAR_MAP, include_types=None):
    """
    Convert parse_sonarqube() output into a list of unified Finding objects.

    Parameters
    ----------
    include_types : iterable[str] or None
        If given (e.g. {"VULNERABILITY"}), issues whose 'type' is not in
        this set are dropped entirely -- this is "Option 2": filtering
        non-security SonarQube issue types (BUG, CODE_SMELL) out of the
        comparison at the toolkit level, without needing to re-export from
        SonarQube. Comparison is case-insensitive. If None (default), every
        issue in the file is normalised, matching the tool's raw output.
    """
    cwe_map = _load_cwe_map(cwe_map_path)
    include_set = {t.upper() for t in include_types} if include_types else None

    findings = []
    for item in raw_issues:
        issue_type = (item.get("type") or "UNKNOWN").upper()
        if include_set is not None and issue_type not in include_set:
            continue

        rule = item.get("rule") or ""
        cwe = cwe_map.get(rule, "CWE-UNKNOWN")

        findings.append(Finding(
            tool="SonarQube",
            file=normalise_path(item.get("file")),
            line=int(item.get("line") or 0),
            end_line=int(item.get("end_line") or item.get("line") or 0),
            rule_id=rule,
            cwe=cwe,
            severity=_SONAR_SEVERITY_MAP.get((item.get("severity") or "").upper(), "MEDIUM"),
            issue_type=issue_type,
            message=item.get("message") or "",
        ))
    return findings


def load_and_normalise(tool, path, cwe_map_path=None, include_types=None):
    """One-call convenience wrapper: parse a raw JSON file straight into a
    list of unified Finding objects, dispatching by tool name.
    `include_types` is only meaningful for tool="sonarqube" (see
    normalise_sonarqube)."""
    tool_key = tool.strip().lower()
    if tool_key == "bandit":
        raw = parse_bandit(path)
        return normalise_bandit(raw, cwe_map_path or _DEFAULT_BANDIT_MAP)
    elif tool_key == "sonarqube":
        raw = parse_sonarqube(path)
        return normalise_sonarqube(raw, cwe_map_path or _DEFAULT_SONAR_MAP, include_types=include_types)
    else:
        raise ValueError(f"Unknown tool '{tool}'. Supported: bandit, sonarqube")
