"""
metrics_calculator.py
----------------------
Component 4: MetricsCalculator

Implements the standard detection-accuracy formulas -- Precision, Recall,
and F1-Score -- from a `ground_truth_matcher.MatchResult`.

    Precision = TP / (TP + FP)   -- of everything the tool flagged, how much was real
    Recall    = TP / (TP + FN)   -- of everything that was real, how much did the tool find
    F1        = 2 * (Precision * Recall) / (Precision + Recall)

All three are defined to be 0.0 (rather than raising a ZeroDivisionError)
when their denominator is zero, which is the conventional choice for this
kind of evaluation.
"""

from dataclasses import dataclass


@dataclass
class Metrics:
    tool: str
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float

    def as_dict(self):
        return {
            "tool": self.tool,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1, 4),
        }


def calculate_metrics(match_result):
    """Compute Precision/Recall/F1 for a single tool's MatchResult."""
    tp = len(match_result.tp)
    fp = len(match_result.fp)
    fn = len(match_result.fn)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return Metrics(tool=match_result.tool, tp=tp, fp=fp, fn=fn,
                    precision=precision, recall=recall, f1=f1)


def calculate_all(match_results):
    """Convenience helper: compute Metrics for a list/dict of MatchResults."""
    if isinstance(match_results, dict):
        match_results = match_results.values()
    return [calculate_metrics(mr) for mr in match_results]
