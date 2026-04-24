US-08: STRIDE Manual vs Automated Comparison
=============================================

OVERVIEW
--------
This toolkit compares the automated STRIDE agent output against two manual
STRIDE analyses (insecure and secure scenarios) and generates quantitative
metrics (Precision, Recall, F1, STRIDE Coverage, TP/FP/FN).


FILES
-----
  manual-analysis-insecure.json   Manual STRIDE analysis - insecure scenario
  manual-analysis-secure.json     Manual STRIDE analysis - secure scenario
  compare.js                      Comparison script (Node.js, no dependencies)
  metrics-report.json             Generated JSON metrics report
  metrics-report.html             Generated HTML metrics report
  docs/metrics-formulas.md        Formulas, definitions, and worked example


REQUIREMENTS
------------
  - Node.js 14 or later (no external npm packages required)


RUNNING THE COMPARISON
----------------------
From the repository root:

  node compare.js

This will:
  1. Load manual-analysis-insecure.json and manual-analysis-secure.json
  2. Load Attack-Simulation-FDSI/combined-report.json (automated source)
  3. Compute TP / FP / FN using normalised threat IDs
  4. Calculate Precision, Recall, F1, and STRIDE Coverage
  5. Write metrics-report.json
  6. Write metrics-report.html
  7. Print a summary to the console

Console output example:
  Precision       : 70.0%
  Recall          : 77.8%
  F1 Score        : 73.7%
  STRIDE Coverage : 80.0%
  True Positives  : 7
  False Positives : 3
  False Negatives : 2


CUSTOM INPUT PATHS (CLI)
------------------------
You can override the default file paths:

  node compare.js \
    --manual-insecure path/to/manual-insecure.json \
    --manual-secure   path/to/manual-secure.json \
    --automated       path/to/automated-report.json

The automated JSON must contain a "combined_threats" array with objects
having at minimum: category, component, severity.


READING THE REPORTS
-------------------
metrics-report.json
  Open with any text editor or JSON viewer.
  Structure:
    {
      "metadata": { timestamp, input file paths },
      "global":   { precision, recall, f1, strideCoverage, counts,
                    bySeverity, byCategory, details: { tp, fp, fn } },
      "scenarios": {
        "insecure": { ... same fields ... },
        "secure":   { ... same fields ... }
      }
    }

metrics-report.html
  Open directly in any modern web browser (no server required):
    - On Linux/Mac:  open metrics-report.html
    - On Windows:    start metrics-report.html
    - Or drag the file into a browser window.

  The HTML report shows:
    - Cards: Precision / Recall / F1 / STRIDE Coverage / TP / FP / FN
    - Global STRIDE category breakdown table
    - Tabbed view for Insecure and Secure scenarios
    - Per-scenario category and severity tables
    - Expandable detail sections for FP, FN, and TP items


METRIC DEFINITIONS
------------------
  TP (True Positive)   - Threat found by BOTH automated tool AND manual analyst
  FP (False Positive)  - Threat found ONLY by automated tool (false alarm)
  FN (False Negative)  - Threat found ONLY by manual analyst (missed by tool)

  Precision = TP / (TP + FP)
  Recall    = TP / (TP + FN)
  F1        = 2 * Precision * Recall / (Precision + Recall)
  STRIDE Coverage = categories covered by >=1 TP / categories in manual

  See docs/metrics-formulas.md for full definitions and a worked example.


THREAT ID NORMALISATION
-----------------------
Each threat is identified by:
  id = normalize(category) + '|' + normalize(component) + '|' + normalize(severity)

  normalize() = lowercase, remove spaces and punctuation

This makes matching robust to minor formatting differences between sources.


SCENARIOS
---------
  insecure  An intentionally vulnerable system with many threats.
            Manual analysis found 8 threats (including Repudiation and
            Hardcoded Credentials not detected by auto).

  secure    A hardened system after mitigations.
            Manual analysis found 1 residual low-severity threat.
            High FP count shows auto over-reports on secure systems.
