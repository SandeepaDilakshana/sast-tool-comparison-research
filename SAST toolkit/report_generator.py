"""
report_generator.py
---------------------
Component 5: Report Generator

Compiles Metrics + MatchResult objects into a final comparison report,
exportable as CSV or JSON for further review/decision-making.

Two report shapes are produced:
  1. A summary table -- one row per tool with TP/FP/FN/Precision/Recall/F1.
  2. A detailed findings table -- one row per GT entry per tool, showing
     whether it was a TP or FN, plus every FP the tool raised. Useful for
     manually auditing *why* a tool scored the way it did.
"""

import csv
import json
from datetime import datetime, timezone


def _summary_rows(metrics_list):
    return [m.as_dict() for m in metrics_list]


def _detail_rows(match_results):
    """Flatten every MatchResult into per-row detail records."""
    if isinstance(match_results, dict):
        match_results = match_results.values()

    rows = []
    for mr in match_results:
        for finding, gt in mr.tp:
            rows.append({
                "tool": mr.tool,
                "status": "TP",
                "gt_id": gt.gt_id,
                "vulnerability_type": gt.vulnerability_type,
                "cwe": ", ".join(gt.cwe_list),
                "severity": gt.severity,
                "issue_type": finding.issue_type,
                "matched_file": finding.file,
                "matched_line": finding.line,
                "rule_id": finding.rule_id,
                "message": finding.message,
            })
        for gt in mr.fn:
            rows.append({
                "tool": mr.tool,
                "status": "FN",
                "gt_id": gt.gt_id,
                "vulnerability_type": gt.vulnerability_type,
                "cwe": ", ".join(gt.cwe_list),
                "severity": gt.severity,
                "issue_type": "",
                "matched_file": "",
                "matched_line": "",
                "rule_id": "",
                "message": "Not detected by this tool",
            })
        for finding in mr.fp:
            rows.append({
                "tool": mr.tool,
                "status": "FP",
                "gt_id": "",
                "vulnerability_type": "",
                "cwe": finding.cwe,
                "severity": finding.severity,
                "issue_type": finding.issue_type,
                "matched_file": finding.file,
                "matched_line": finding.line,
                "rule_id": finding.rule_id,
                "message": finding.message,
            })
    return rows


def generate_report(metrics_list, match_results, out_path, fmt="csv"):
    """
    Write the final comparison report to disk.

    Parameters
    ----------
    metrics_list : list[metrics_calculator.Metrics]
    match_results : dict[str, ground_truth_matcher.MatchResult] or list of MatchResult
    out_path : str        -- destination file path (extension is respected but
                              not enforced; pass whatever the user chose in the
                              save dialog)
    fmt : "csv" | "json"
    """
    summary = _summary_rows(metrics_list)
    details = _detail_rows(match_results)

    if fmt.lower() == "json":
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "details": details,
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    elif fmt.lower() == "csv":
        # CSV can't hold two differently-shaped tables in one file cleanly,
        # so we write a combined file: a SUMMARY block, then a DETAILS block.
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            f.write(f"# SAST Tool Comparison Report - generated {datetime.now(timezone.utc).isoformat()}\n")
            f.write("# --- SUMMARY ---\n")
            if summary:
                w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
                w.writeheader()
                w.writerows(summary)
            f.write("\n# --- DETAILS ---\n")
            if details:
                w = csv.DictWriter(f, fieldnames=list(details[0].keys()))
                w.writeheader()
                w.writerows(details)
    else:
        raise ValueError("fmt must be 'csv' or 'json'")

    return out_path
