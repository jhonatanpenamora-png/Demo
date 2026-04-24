# STRIDE Comparison Metrics – Formulas and Definitions

This document describes the methodology used by `compare.js` to evaluate the quality of the automated STRIDE agent against a manual human analysis.

---

## 1. Ground Truth and Roles

| Role | Source |
|------|--------|
| **Ground Truth (manual)** | `manual-analysis-insecure.json` / `manual-analysis-secure.json` |
| **Automated output** | `Attack-Simulation-FDSI/combined-report.json` → `combined_threats` |

The manual analysis is treated as the reference. The automated tool is evaluated against it.

---

## 2. Threat Normalisation and ID Generation

Each threat item is reduced to a **deterministic ID** to allow exact matching between the two sources:

```
id = normalize(category) + '|' + normalize(component) + '|' + normalize(severity)
```

Where `normalize(str)`:
1. Converts to lowercase
2. Trims leading/trailing whitespace
3. Collapses all internal whitespace (removes spaces)
4. Removes non-alphanumeric characters (keeps only `a-z`, `0-9`)

**Examples:**

| Raw value | Normalized |
|-----------|-----------|
| `"Information Disclosure"` | `informationdisclosure` |
| `"InformationDisclosure"` | `informationdisclosure` |
| `"SQL Injection Attack"` | `sqlinjectionattack` |
| `"Alta"` | `alta` |

This ensures that minor formatting differences (spaces, capitalisation, punctuation) do not affect matching.

If `component` is empty, the `description` field is used as a fallback.

---

## 3. Definitions: TP, FP, FN

| Term | Definition |
|------|-----------|
| **True Positive (TP)** | A threat detected by the **automated** tool that **also exists** in the manual analysis. The automated tool correctly identified a real threat. |
| **False Positive (FP)** | A threat detected by the **automated** tool that **does NOT exist** in the manual analysis. The automated tool raised a false alarm. |
| **False Negative (FN)** | A threat present in the **manual** analysis that was **NOT detected** by the automated tool. The automated tool missed a real threat. |

---

## 4. Precision

> Of all threats the automated tool reported, what fraction were real (confirmed by manual analysis)?

```
Precision = TP / (TP + FP)
```

- Range: 0.0 (no correct detections) → 1.0 (all detections correct)
- Returns `null` / `N/A` when `TP + FP = 0` (no automated detections).

---

## 5. Recall (Sensitivity)

> Of all threats a human analyst found, what fraction did the automated tool also detect?

```
Recall = TP / (TP + FN)
```

- Range: 0.0 (nothing detected) → 1.0 (all manual threats detected)
- Returns `null` / `N/A` when `TP + FN = 0` (no manual threats to find).

---

## 6. F1 Score

> Harmonic mean of Precision and Recall; a single balanced measure.

```
F1 = 2 × (Precision × Recall) / (Precision + Recall)
```

- Returns `null` / `N/A` when either metric is `null` or when both are `0`.

---

## 7. STRIDE Coverage

> Of the STRIDE categories a human analyst identified threats in, what fraction did the automated tool cover (with at least one TP)?

```
STRIDE Coverage = |categories covered by ≥1 TP| / |categories present in manual|
```

- A category is **present in manual** if at least one manual threat belongs to it.
- A category is **covered** if at least one TP belongs to it.
- Returns `null` / `N/A` when the manual analysis has no threats.

STRIDE categories tracked:
- **S**poofing
- **T**ampering
- **R**epudiation
- **I**nformation Disclosure (`InformationDisclosure`)
- **D**enial of Service (`DenialOfService`)
- **E**levation of Privilege (`ElevationOfPrivilege`)

---

## 8. Worked Example

Suppose the automated tool reports 5 threats, and the manual analysis identifies 4 threats.

| Threat ID | In Manual? | In Auto? | Classification |
|-----------|-----------|---------|---------------|
| `spoofing\|corsattack\|alta` | ✅ | ✅ | **TP** |
| `tampering\|sqlinjectionattack\|alta` | ✅ | ✅ | **TP** |
| `informationdisclosure\|pathtraversalattack\|alta` | ✅ | ✅ | **TP** |
| `spoofing\|sessionfixationattack\|media` | ❌ | ✅ | **FP** |
| `denialofservice\|bruteforceattack\|baja` | ❌ | ✅ | **FP** |
| `repudiation\|auditlogtampering\|media` | ✅ | ❌ | **FN** |

**Counts:** TP = 3, FP = 2, FN = 1

**Precision** = 3 / (3 + 2) = **0.60** (60%)

**Recall** = 3 / (3 + 1) = **0.75** (75%)

**F1** = 2 × (0.60 × 0.75) / (0.60 + 0.75) = **0.667** (66.7%)

**Manual categories present:** Spoofing, Tampering, InformationDisclosure, Repudiation → 4  
**Categories covered by TP:** Spoofing, Tampering, InformationDisclosure → 3  
**STRIDE Coverage** = 3 / 4 = **0.75** (75%)

---

## 9. Division-by-Zero Handling

The script handles all edge cases where denominators could be zero:

| Condition | Behaviour |
|-----------|-----------|
| No automated threats (`TP + FP = 0`) | `precision = null` |
| No manual threats (`TP + FN = 0`) | `recall = null` |
| Both null or both zero | `f1 = null` |
| No manual threats (coverage) | `strideCoverage = null` |

`null` values are displayed as `N/A` in reports.
