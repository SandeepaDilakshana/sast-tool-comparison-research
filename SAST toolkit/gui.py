"""
gui.py
------
Simple Tkinter GUI for the PyGoat SAST Evaluation Toolkit.

Ties together the five core components:
    1. result_parser.py          (Result Parser Module)
    2. normalizer.py              (Output Normalisation Module)
    3. ground_truth_matcher.py    (GroundTruthMatcher)
    4. metrics_calculator.py      (MetricsCalculator)
    5. report_generator.py        (Report Generator)

Each pipeline stage has its own button so the workflow is fully visible
and inspectable step by step:

    [Load Ground Truth]  ->  [Load Bandit JSON]  ->  [Load SonarQube JSON]
              |                                              |
              +--------------------> [Run Matching] <--------+
                                            |
                                    [Calculate Metrics]
                                            |
                                    [Generate Report]

SonarQube issue-type filtering ("Option 2"):
SonarQube's default profile reports BUG and CODE_SMELL issues alongside
VULNERABILITY issues. Comparing an unfiltered export against a
security-only ground truth (and against Bandit, a security-only tool)
inflates False Positives with issues that were never meant to be security
findings. Tick "Only score SonarQube 'VULNERABILITY' type issues" to
exclude BUG/CODE_SMELL from the comparison -- this re-applies instantly to
whatever SonarQube file is already loaded, no need to reload it. The
complementary "Option 1" (filtering at the SonarQube export/API level, e.g.
`types=VULNERABILITY` on `/api/issues/search`) is documented in README.md.

Run with:  python gui.py
(Requires only the Python standard library -- Tkinter ships with most
standard Python installations. On some minimal Linux setups you may need
`sudo apt-get install python3-tk`.)
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import result_parser as rp
import normalizer
import ground_truth_matcher as gtm
import metrics_calculator as mc
import report_generator as rg


class SastToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PyGoat SAST Evaluation Toolkit")
        self.root.geometry("1080x700")

        # ---- application state ----
        self.gt_entries = []
        self.gt_path = None
        self.findings = {"Bandit": [], "SonarQube": []}
        self.loaded_paths = {"Bandit": None, "SonarQube": None}
        self.raw_sonar_issues = None   # raw parsed SonarQube issues, kept so the
                                        # type filter can be re-applied without reloading
        self.match_results = {}        # tool -> MatchResult
        self.metrics_list = []         # list[Metrics]

        self.line_tolerance = tk.IntVar(value=3)
        self.exclude_non_detectable = tk.BooleanVar(value=False)
        self.sonar_vuln_only = tk.BooleanVar(value=False)

        self._build_layout()

    # ------------------------------------------------------------------ UI

    def _build_layout(self):
        # ---- top control panel ----
        control = ttk.Frame(self.root, padding=10)
        control.pack(side="top", fill="x")

        row1 = ttk.Frame(control)
        row1.pack(fill="x", pady=2)
        ttk.Label(row1, text="Step 1 - Load Data:", width=18, anchor="w").pack(side="left")
        ttk.Button(row1, text="Load Ground Truth CSV",
                   command=self.load_ground_truth).pack(side="left", padx=4)
        ttk.Button(row1, text="Load Bandit JSON",
                   command=lambda: self.load_tool_results("Bandit")).pack(side="left", padx=4)
        ttk.Button(row1, text="Load SonarQube JSON",
                   command=lambda: self.load_tool_results("SonarQube")).pack(side="left", padx=4)

        row1b = ttk.Frame(control)
        row1b.pack(fill="x", pady=(0, 4))
        ttk.Label(row1b, text="", width=18).pack(side="left")
        ttk.Checkbutton(row1b, text="Only score SonarQube 'VULNERABILITY' type issues "
                                     "(exclude BUG / CODE_SMELL)",
                         variable=self.sonar_vuln_only,
                         command=self._on_sonar_filter_toggle).pack(side="left")

        row2 = ttk.Frame(control)
        row2.pack(fill="x", pady=6)
        ttk.Label(row2, text="Step 2 - Evaluate:", width=18, anchor="w").pack(side="left")
        ttk.Button(row2, text="Run Ground Truth Matching",
                   command=self.run_matching).pack(side="left", padx=4)
        ttk.Button(row2, text="Calculate Metrics",
                   command=self.run_metrics).pack(side="left", padx=4)
        ttk.Button(row2, text="Generate Report (CSV/JSON)",
                   command=self.generate_report).pack(side="left", padx=4)
        ttk.Button(row2, text="Reset All",
                   command=self.reset_all).pack(side="left", padx=12)

        row3 = ttk.Frame(control)
        row3.pack(fill="x", pady=2)
        ttk.Label(row3, text="Line tolerance (+/-):").pack(side="left")
        ttk.Spinbox(row3, from_=0, to=20, width=5,
                    textvariable=self.line_tolerance).pack(side="left", padx=(4, 20))
        ttk.Checkbutton(row3, text="Exclude GT entries not detectable by Python-only SAST",
                         variable=self.exclude_non_detectable).pack(side="left")

        # ---- status strip ----
        self.status_var = tk.StringVar(
            value="Ready. Load a ground-truth CSV and at least one tool's JSON output to begin.")
        ttk.Label(self.root, textvariable=self.status_var, anchor="w",
                  relief="sunken", padding=4).pack(side="bottom", fill="x")

        # ---- notebook: Log / Metrics / Details ----
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # --- Log tab ---
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Log")
        self.log_text = tk.Text(log_frame, wrap="word", state="disabled", font=("Consolas", 10))
        log_scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

        # --- Metrics summary tab ---
        metrics_frame = ttk.Frame(self.notebook)
        self.notebook.add(metrics_frame, text="Metrics Summary")
        metrics_cols = ("tool", "tp", "fp", "fn", "precision", "recall", "f1_score")
        self.metrics_tree = ttk.Treeview(metrics_frame, columns=metrics_cols, show="headings", height=10)
        for col, width in zip(metrics_cols, (120, 60, 60, 60, 100, 100, 100)):
            self.metrics_tree.heading(col, text=col.upper())
            self.metrics_tree.column(col, width=width, anchor="center")
        self.metrics_tree.pack(fill="both", expand=True, padx=5, pady=5)

        # --- Detailed matches tab ---
        details_frame = ttk.Frame(self.notebook)
        self.notebook.add(details_frame, text="Detailed Matches")
        detail_cols = ("tool", "status", "gt_id", "vulnerability_type", "cwe",
                       "severity", "issue_type", "matched_file", "matched_line", "rule_id")
        self.details_tree = ttk.Treeview(details_frame, columns=detail_cols, show="headings", height=10)
        widths = (80, 60, 60, 170, 90, 80, 100, 210, 90, 90)
        for col, width in zip(detail_cols, widths):
            self.details_tree.heading(col, text=col.upper())
            self.details_tree.column(col, width=width, anchor="w")
        detail_scroll_y = ttk.Scrollbar(details_frame, command=self.details_tree.yview)
        detail_scroll_x = ttk.Scrollbar(details_frame, orient="horizontal", command=self.details_tree.xview)
        self.details_tree.configure(yscrollcommand=detail_scroll_y.set, xscrollcommand=detail_scroll_x.set)
        self.details_tree.pack(side="top", fill="both", expand=True, padx=5, pady=(5, 0))
        detail_scroll_x.pack(side="bottom", fill="x", padx=5)
        detail_scroll_y.pack(side="right", fill="y")

    # --------------------------------------------------------------- helpers

    def _log(self, message):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    def _set_status(self, message):
        self.status_var.set(message)

    # --------------------------------------------------------- button actions

    def load_ground_truth(self):
        path = filedialog.askopenfilename(
            title="Select ground-truth manifest CSV",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            self.gt_entries = gtm.load_ground_truth(path)
            self.gt_path = path
            self._log(f"[Ground Truth] Loaded {len(self.gt_entries)} entries from: {path}")
            self._set_status(f"Ground truth loaded: {len(self.gt_entries)} entries.")
        except Exception as e:
            messagebox.showerror("Error loading ground truth", str(e))
            self._log(f"[Ground Truth] ERROR: {e}")

    def load_tool_results(self, tool):
        path = filedialog.askopenfilename(
            title=f"Select {tool} JSON output",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            if tool == "SonarQube":
                # Parse raw first (kept in memory) so the type-filter checkbox
                # can be toggled afterwards without re-opening the file dialog.
                raw = rp.parse_sonarqube(path)
                self.raw_sonar_issues = raw
                self.loaded_paths[tool] = path

                type_counts = normalizer.summarize_issue_types(raw)
                breakdown = ", ".join(f"{k}={v}" for k, v in sorted(type_counts.items()))
                self._log(f"[SonarQube] Parsed {len(raw)} raw issues from: {path}")
                self._log(f"[SonarQube] Issue type breakdown: {breakdown}")

                self._apply_sonar_filter()
            else:
                findings = normalizer.load_and_normalise(tool, path)
                self.findings[tool] = findings
                self.loaded_paths[tool] = path
                self._log(f"[{tool}] Parsed & normalised {len(findings)} findings from: {path}")
                self._set_status(f"{tool}: {len(findings)} findings loaded.")
        except Exception as e:
            messagebox.showerror(f"Error loading {tool} results", str(e))
            self._log(f"[{tool}] ERROR: {e}")

    def _apply_sonar_filter(self):
        """Re-normalise the already-loaded raw SonarQube issues using the
        current state of the 'VULNERABILITY only' checkbox. Safe to call
        repeatedly (e.g. every time the checkbox is toggled)."""
        if self.raw_sonar_issues is None:
            return
        include_types = {"VULNERABILITY"} if self.sonar_vuln_only.get() else None
        findings = normalizer.normalise_sonarqube(self.raw_sonar_issues, include_types=include_types)
        self.findings["SonarQube"] = findings

        mode = "VULNERABILITY-only" if include_types else "all issue types"
        self._log(f"[SonarQube] Normalised {len(findings)} findings after filter ({mode}).")
        self._set_status(f"SonarQube: {len(findings)} findings loaded ({mode}). "
                          f"Re-run matching to refresh results.")

    def _on_sonar_filter_toggle(self):
        self._apply_sonar_filter()

    def run_matching(self):
        if not self.gt_entries:
            messagebox.showwarning("Missing data", "Load the ground-truth CSV first.")
            return
        active_tools = [t for t, f in self.findings.items() if f]
        if not active_tools:
            messagebox.showwarning("Missing data", "Load at least one tool's JSON output first.")
            return

        tolerance = self.line_tolerance.get()
        exclude = self.exclude_non_detectable.get()
        self.match_results = {}

        for tool in active_tools:
            mr = gtm.match(self.findings[tool], self.gt_entries,
                            line_tolerance=tolerance,
                            exclude_non_detectable=exclude,
                            tool_name=tool)
            self.match_results[tool] = mr
            self._log(f"[Matching:{tool}] TP={len(mr.tp)}  FP={len(mr.fp)}  FN={len(mr.fn)} "
                       f"(tolerance=+/-{tolerance}, exclude_non_detectable={exclude})")

        self._populate_details_tree()
        self._set_status("Matching complete. See 'Detailed Matches' tab, then click 'Calculate Metrics'.")

    def run_metrics(self):
        if not self.match_results:
            messagebox.showwarning("Missing data", "Run ground-truth matching first.")
            return
        self.metrics_list = mc.calculate_all(self.match_results)
        self._populate_metrics_tree()
        for m in self.metrics_list:
            self._log(f"[Metrics:{m.tool}] Precision={m.precision:.3f}  "
                       f"Recall={m.recall:.3f}  F1={m.f1:.3f}")
        self._set_status("Metrics calculated. See 'Metrics Summary' tab.")
        self.notebook.select(1)

    def generate_report(self):
        if not self.metrics_list:
            messagebox.showwarning("Missing data", "Calculate metrics first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save comparison report as...",
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv"), ("JSON file", "*.json")])
        if not path:
            return
        fmt = "json" if path.lower().endswith(".json") else "csv"
        try:
            rg.generate_report(self.metrics_list, self.match_results, path, fmt=fmt)
            self._log(f"[Report] Saved {fmt.upper()} report to: {path}")
            self._set_status(f"Report saved: {path}")
            messagebox.showinfo("Report generated", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error generating report", str(e))
            self._log(f"[Report] ERROR: {e}")

    def reset_all(self):
        self.gt_entries = []
        self.gt_path = None
        self.findings = {"Bandit": [], "SonarQube": []}
        self.loaded_paths = {"Bandit": None, "SonarQube": None}
        self.raw_sonar_issues = None
        self.match_results = {}
        self.metrics_list = []
        self.sonar_vuln_only.set(False)
        self.exclude_non_detectable.set(False)
        self.line_tolerance.set(3)
        for tree in (self.metrics_tree, self.details_tree):
            for item in tree.get_children():
                tree.delete(item)
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self._set_status("Reset. Load a ground-truth CSV and at least one tool's JSON output to begin.")

    # ----------------------------------------------------------- tree fill-in

    def _populate_metrics_tree(self):
        for item in self.metrics_tree.get_children():
            self.metrics_tree.delete(item)
        for m in self.metrics_list:
            d = m.as_dict()
            self.metrics_tree.insert("", "end", values=(
                d["tool"], d["tp"], d["fp"], d["fn"],
                f'{d["precision"]:.3f}', f'{d["recall"]:.3f}', f'{d["f1_score"]:.3f}'))

    def _populate_details_tree(self):
        for item in self.details_tree.get_children():
            self.details_tree.delete(item)
        for tool, mr in self.match_results.items():
            for finding, gt in mr.tp:
                self.details_tree.insert("", "end", values=(
                    tool, "TP", gt.gt_id, gt.vulnerability_type, ", ".join(gt.cwe_list),
                    gt.severity, finding.issue_type, finding.file, finding.line, finding.rule_id))
            for gt in mr.fn:
                self.details_tree.insert("", "end", values=(
                    tool, "FN", gt.gt_id, gt.vulnerability_type, ", ".join(gt.cwe_list),
                    gt.severity, "-", "-", "-", "-"))
            for finding in mr.fp:
                self.details_tree.insert("", "end", values=(
                    tool, "FP", "-", "-", finding.cwe,
                    finding.severity, finding.issue_type, finding.file, finding.line, finding.rule_id))


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except tk.TclError:
        pass
    app = SastToolkitApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
