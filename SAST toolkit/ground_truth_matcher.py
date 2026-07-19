"""
ground_truth_matcher.py
------------------------
Component 3: GroundTruthMatcher

Loads a ground-truth manifest (the CSV format produced for the PyGoat
benchmark: GT_ID, File, Lines, Vulnerability_Type, CWE_ID, Severity,
Python_SAST_Detectable, ...) and compares a list of normalised `Finding`
objects (from normalizer.py) against it, classifying each ground-truth
vulnerability as detected (True Positive) or missed (False Negative), and
each tool finding that matches nothing as a False Positive.

Matching is done at the *vulnerability level* (one GT entry == one TP/FN),
not the line level: a GT entry counts as detected the moment ANY tool
finding lands in the right file within the GT entry's line range(s)
(+/- a configurable tolerance, to absorb small line-number drift between
the ground truth and a tool's reported line).

Design note: real-world ground-truth manifests are written by humans and
are messy on purpose (e.g. "approx. line 29-31", "last line", entries that
span two files). `_parse_line_spec` and `_parse_file_spec` below are
deliberately forgiving so the matcher keeps working on that kind of input
without every row needing to be machine-perfect.
"""

import csv
import re
from dataclasses import dataclass, field


@dataclass
class GTEntry:
    gt_id: str
    files: list
    line_ranges: list      # list of (start, end) inclusive tuples; [] means "match anywhere in file"
    cwe_list: list
    vulnerability_type: str
    severity: str
    detectable: str        # "Yes" | "No" | "Partial"
    description: str


@dataclass
class MatchResult:
    tool: str
    tp: list = field(default_factory=list)   # list of (Finding, GTEntry)
    fp: list = field(default_factory=list)   # list of Finding
    fn: list = field(default_factory=list)   # list of GTEntry


def _parse_file_spec(raw):
    """'a.py / b.py' or 'a.py; b.py' -> ['a.py', 'b.py']. A lone 'a.py' -> ['a.py'].
    Splits only on slash/semicolon *surrounded by whitespace* so real path
    separators (no surrounding spaces) are left untouched."""
    if not raw:
        return []
    parts = re.split(r'\s*/\s+|\s*;\s*', raw.strip())
    return [p.strip().replace("\\", "/") for p in parts if p.strip()]


def _parse_line_spec(raw):
    """Extract line ranges from a free-text 'Lines' cell.
    '93-101' -> [(93,101)] ; '158,162' -> [(158,158),(162,162)]
    '202,205-219' -> [(202,202),(205,219)]
    'approx. line 29-31' -> [(29,31)] ; 'last line' -> [] (=> match anywhere in file)
    """
    if not raw:
        return []
    ranges = []
    for m in re.finditer(r'(\d+)\s*-\s*(\d+)', raw):
        ranges.append((int(m.group(1)), int(m.group(2))))
    stripped = re.sub(r'\d+\s*-\s*\d+', ' ', raw)
    for m in re.finditer(r'\d+', stripped):
        n = int(m.group(0))
        ranges.append((n, n))
    return ranges


def _parse_cwe_spec(raw):
    if not raw:
        return []
    return [c.strip() for c in re.split(r'\s*/\s*', raw) if c.strip().upper().startswith("CWE")]


def _parse_detectable(raw):
    if not raw:
        return "Unknown"
    m = re.match(r'\s*(Yes|No|Partial)', raw, re.IGNORECASE)
    return m.group(1).capitalize() if m else "Unknown"


def load_ground_truth(csv_path):
    """Load the ground-truth manifest CSV into a list of GTEntry objects."""
    entries = []
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entries.append(GTEntry(
                gt_id=row.get("GT_ID", "").strip(),
                files=_parse_file_spec(row.get("File", "")),
                line_ranges=_parse_line_spec(row.get("Lines", "")),
                cwe_list=_parse_cwe_spec(row.get("CWE_ID", "")),
                vulnerability_type=row.get("Vulnerability_Type", "").strip(),
                severity=row.get("Severity", "").strip(),
                detectable=_parse_detectable(row.get("Python_SAST_Detectable", "")),
                description=row.get("Description", "").strip(),
            ))
    return entries


def _file_matches(finding_file, gt_files):
    if not finding_file or not gt_files:
        return False
    ff = finding_file.replace("\\", "/").lower()
    for gf in gt_files:
        gf_norm = gf.replace("\\", "/").lower()
        if ff == gf_norm or ff.endswith("/" + gf_norm) or gf_norm.endswith("/" + ff):
            return True
        # Fall back to basename match (handles differing repo-root prefixes)
        if ff.split("/")[-1] == gf_norm.split("/")[-1]:
            return True
    return False


def _line_matches(line, line_ranges, tolerance):
    if not line_ranges:
        return True  # no usable line info in the GT row -> match anywhere in the file
    for start, end in line_ranges:
        if (start - tolerance) <= line <= (end + tolerance):
            return True
    return False


def match(findings, gt_entries, line_tolerance=3, exclude_non_detectable=False, tool_name=None):
    """
    Compare a single tool's findings against the ground truth.

    Parameters
    ----------
    findings : list[normalizer.Finding]   -- findings from ONE tool
    gt_entries : list[GTEntry]
    line_tolerance : int    -- +/- lines of slack when matching a finding's
                                line number against a GT entry's line range
    exclude_non_detectable : bool -- if True, GT entries flagged
                                'No' (not detectable by Python-only static
                                analysis) are removed from the scoring
                                universe entirely (recommended secondary
                                metric -- see README methodology notes)
    tool_name : str, optional override for the result's tool label

    Returns
    -------
    MatchResult
    """
    scoring_gt = [g for g in gt_entries if not (exclude_non_detectable and g.detectable == "No")]

    tp = []
    fn = []
    matched_finding_ids = set()

    for gt in scoring_gt:
        hit = None
        for idx, f in enumerate(findings):
            if _file_matches(f.file, gt.files) and _line_matches(f.line, gt.line_ranges, line_tolerance):
                hit = f
                matched_finding_ids.add(idx)
                break
        if hit is not None:
            tp.append((hit, gt))
        else:
            fn.append(gt)

    fp = [f for idx, f in enumerate(findings) if idx not in matched_finding_ids]

    label = tool_name or (findings[0].tool if findings else "Unknown")
    return MatchResult(tool=label, tp=tp, fp=fp, fn=fn)
