# PyGoat SAST Evaluation Toolkit

A simple Python toolkit that automates comparing SAST tool output (Bandit,
SonarQube) against a ground-truth vulnerability manifest, and reports
Precision / Recall / F1-Score per tool -- with a Tkinter GUI so each step
can be triggered by a button.

## The 5 components (as specified)

| # | File | Component |
|---|---|---|
| 1 | `result_parser.py` | **Result Parser Module** -- reads raw Bandit/SonarQube JSON and extracts file, line, rule ID, severity, CWE (where present). |
| 2 | `normalizer.py` | **Output Normalisation Module** -- maps both tools' native fields into one unified `Finding` schema. |
| 3 | `ground_truth_matcher.py` | **GroundTruthMatcher** -- loads the ground-truth CSV and classifies each GT entry as detected (TP) or missed (FN); unmatched tool findings become FP. |
| 4 | `metrics_calculator.py` | **MetricsCalculator** -- Precision, Recall, F1-Score from TP/FP/FN. |
| 5 | `report_generator.py` | **Report Generator** -- exports a summary + detailed-findings report as CSV or JSON. |
| - | `gui.py` | Tkinter front-end wiring all five together with one button per action. |

## Requirements

- Python 3.8+
- No third-party packages -- everything uses the standard library
  (`json`, `csv`, `dataclasses`, `tkinter`).
- On minimal Linux installs, Tkinter may need a separate package:
  `sudo apt-get install python3-tk` (Windows/macOS installers normally
  include it already).

## Running the GUI

```bash
cd sast_toolkit
python gui.py
```

### Workflow (matches the button layout top-to-bottom)

1. **Load Ground Truth CSV** -- select your ground-truth manifest
   (see `sample_data/ground_truth_manifest.csv` for the exact expected
   column layout: `GT_ID, File, Lines, Function_Scope, Vulnerability_Type,
   CWE_ID, OWASP_Top10_2021, Severity, Python_SAST_Detectable, Description,
   Code_Reference`).
2. **Load Bandit JSON** -- select a `bandit -f json -o out.json ...` report.
3. **Load SonarQube JSON** -- select a SonarQube/SonarCloud issues export
   (the JSON shape returned by `GET /api/issues/search`, or a plain list of
   issue objects in that same shape). The Log tab immediately shows a
   breakdown of issue types found (e.g. `VULNERABILITY=19, BUG=48,
   CODE_SMELL=435`) so you can see up front how much of the export is
   security-relevant.
   - **"Only score SonarQube 'VULNERABILITY' type issues" checkbox** --
     SonarQube's default profile reports BUG and CODE_SMELL issues alongside
     VULNERABILITY issues; comparing those against a security-only ground
     truth (and against Bandit, a security-only tool) is not apples-to-apples
     and inflates False Positives. Tick this box to exclude BUG/CODE_SMELL
     from scoring -- it re-applies instantly to the already-loaded file, no
     need to reload. See "SonarQube issue-type filtering" below for the full
     picture (this is "Option 2"; "Option 1" filters even earlier, at export
     time).
4. **Run Ground Truth Matching** -- compares whichever tool(s) you loaded
   against the ground truth. Adjust **line tolerance** (default +/-3) and
   the **exclude non-detectable GT entries** checkbox first if needed.
5. **Calculate Metrics** -- fills in the "Metrics Summary" tab with
   Precision/Recall/F1 per tool.
6. **Generate Report** -- saves a combined summary+detail report as `.csv`
   or `.json` (choose the extension in the save dialog).

Use **Reset All** to clear everything and start over. The **Log** tab
records every step; the **Detailed Matches** tab lets you inspect exactly
which GT entries were hit/missed and which findings were false positives.

## Running without the GUI (scripted / CI use)

Every module works standalone -- see `test_pipeline.py` for a complete
worked example:

```bash
python test_pipeline.py
```

This loads `sample_data/ground_truth_manifest.csv` plus two small sample
tool outputs (`sample_data/sample_bandit_output.json` and
`sample_data/sample_sonarqube_output.json`), runs the full parse ->
normalise -> match -> score -> report pipeline, prints a walkthrough of
every step, and asserts the expected TP/FP/FN counts. Use it as a template
for wiring the toolkit into a GitHub Actions job.

## CWE lookup tables

Bandit (recent versions) embeds a CWE ID directly on each result. SonarQube's
issues API does **not** -- CWE lives in the rule's separate metadata. To keep
the toolkit usable from a plain issues export (no extra API calls), two
small, hand-maintained lookup tables are shipped and used as a fallback:

- `config/bandit_cwe_map.json` -- only used when a Bandit result has no
  embedded `issue_cwe` (older Bandit versions).
- `config/sonar_cwe_map.json` -- used for every SonarQube issue, keyed by
  rule ID (e.g. `python:S2077` -> `CWE-89`).

Both are plain, editable JSON -- add rows for any rule IDs your own Bandit/
SonarQube setup produces that aren't already covered. Unmapped rules resolve
to `CWE-UNKNOWN` rather than failing.

## SonarQube issue-type filtering (Option 1 & Option 2)

**The problem:** SonarQube's default "Sonar way" quality profile reports far
more than security issues -- a typical scan mixes `VULNERABILITY` findings
with `BUG` (reliability) and `CODE_SMELL` (maintainability) findings, which
often outnumber the security findings many times over. Bandit, by contrast,
only ever reports security issues. Comparing an *unfiltered* SonarQube
export against a security-only ground truth is not an apples-to-apples
comparison with Bandit: every non-`VULNERABILITY` issue is close to
guaranteed to be a False Positive, since the ground truth was never going to
contain a "rename this variable" style finding. This is the single biggest
driver of an inflated FP count (and correspondingly collapsed Precision) for
SonarQube in a raw, unfiltered comparison.

Two independent ways to fix this -- **use both together** for the most
defensible methodology:

**Option 1 -- filter at the SonarQube export/API level (outside the toolkit).**
When pulling your issues export, restrict the `types` parameter to security
findings only:

```
GET /api/issues/search?componentKeys=<your-project-key>&types=VULNERABILITY&ps=500
```

This is the cleanest option because the toolkit never even sees the noise.
Note: `SECURITY_HOTSPOT` findings are **not** returned by `/api/issues/search`
at all -- SonarQube exposes them through a separate `/api/hotspots/search`
endpoint with a different JSON shape (`vulnerabilityProbability`, `status`
instead of `severity`, etc.). This toolkit's `result_parser.parse_sonarqube`
does not currently parse that shape -- if you need Security Hotspots
included in your evaluation, treat that as a separate future extension
rather than assuming they're already covered.

**Option 2 -- filter inside the toolkit (GUI checkbox / code-level).**
Tick **"Only score SonarQube 'VULNERABILITY' type issues"** after loading
your SonarQube JSON. Under the hood this calls:

```python
normalizer.normalise_sonarqube(raw_issues, include_types={"VULNERABILITY"})
```

Useful when you don't control the SonarQube export (e.g. someone else ran
the scan and handed you the full JSON), or when you want to compare the
*filtered* and *unfiltered* numbers side by side for your own methodology
discussion -- toggle the checkbox and re-run matching without ever touching
the source file.

Every `Finding` (from either tool) now carries an `issue_type` field
(`"VULNERABILITY"`, `"BUG"`, `"CODE_SMELL"`, or `"UNKNOWN"` for
Bandit findings this is always `"VULNERABILITY"`, since Bandit has no
equivalent concept), visible in the Detailed Matches tab and in every
generated report, so filtered vs. unfiltered runs stay fully auditable.



The matcher expects the same manifest format produced for the PyGoat
benchmark. Two columns need a bit of care if you're hand-editing or
extending it:

- **File** -- one path, or several separated by `" / "` or `"; "`
  (e.g. `"introduction/views.py / introduction/utility.py"`).
- **Lines** -- free-text is tolerated: `"93-101"`, `"158,162"`,
  `"202,205-219"`, `"approx. line 29-31"`, even `"last line"` (treated as
  "match anywhere in the file" when no digits are found).

## Known limitations (please read before citing results)

- **Vulnerability-level scoring, not line-level.** A GT entry counts as
  detected the moment *any* finding lands inside its line range(s) +/-
  tolerance -- this matches standard practice for this kind of evaluation,
  but means the matcher does not check *why* the tool flagged that line.
- **Line-tolerance overlap for closely-clustered GT entries.** If two GT
  entries sit only a few lines apart (this happens in `pygoat/settings.py`,
  where several hardcoded-secret findings are close together) a single tool
  finding can satisfy both, inflating TP count slightly. `test_pipeline.py`
  demonstrates and documents exactly this case. Lower `line_tolerance` to 0
  or 1 if you need strict one-finding-per-GT-entry behaviour, and always
  spot-check the **Detailed Matches** tab rather than trusting the summary
  numbers blindly.
- **File matching falls back to basename comparison** if a full relative
  path doesn't line up (e.g. different repo-root prefixes between your
  ground truth and your tool's working directory). This is convenient but
  can over-match if your project has same-named files in different
  packages -- check the Detailed Matches tab if that applies to you.
- **CWE is informational only in the matcher** -- a finding is not required
  to have the "correct" CWE to count as a TP, only the right file/line. This
  is intentional (tool-reported CWEs for the same underlying bug are often
  inconsistent between Bandit and SonarQube), but it means the toolkit
  currently can't compute a separate "CWE accuracy" metric out of the box.
- **`Python_SAST_Detectable == "No"` entries are included in scoring by
  default.** Tick "Exclude GT entries not detectable by Python-only SAST" to
  get the fairer, tool-realistic recall figure discussed in the ground-truth
  manifest's own methodology notes (business-logic flaws and template-layer
  XSS that no Python-only static analyzer could ever flag).
- **The SonarQube type filter (see above) only distinguishes `VULNERABILITY`
  from `BUG`/`CODE_SMELL`/`UNKNOWN`.** It does not (yet) attempt to separate
  "real" vulnerabilities from SonarQube's own weaker-confidence security
  rules, and it cannot include Security Hotspots at all without a separate
  `/api/hotspots/search` export and a corresponding parser addition.

## File layout

```
sast_toolkit/
├── gui.py                       # Tkinter front-end (run this)
├── result_parser.py             # Component 1
├── normalizer.py                # Component 2
├── ground_truth_matcher.py      # Component 3
├── metrics_calculator.py        # Component 4
├── report_generator.py          # Component 5
├── test_pipeline.py             # non-GUI end-to-end smoke test
├── config/
│   ├── bandit_cwe_map.json
│   └── sonar_cwe_map.json
└── sample_data/
    ├── ground_truth_manifest.csv
    ├── sample_bandit_output.json
    └── sample_sonarqube_output.json
```
