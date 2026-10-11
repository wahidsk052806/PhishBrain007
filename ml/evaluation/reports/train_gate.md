# PhishBrain Prefilter — Training Gate

Generated: 2026-09-23T05:32:13.258860+00:00

Dataset: `data\processed\prefilter_dataset.csv` (train 67016 / test 7959 rows)
Split: time-ordered zero-day split at cutoff 2026-07-02 21:16:31+00:00 (7620 test rows dropped as same-domain-as-training)
Model written to: `backend\models\prefilter.cbm`

## Deployment gate: PASSED (tier: triage)

Tier meaning: triage-grade: acceptable for the 15%-weighted prefilter whose verdict is re-checked by every later layer and disclosed in the report.

Thresholds: {'min_recall': 0.85, 'min_precision': 0.9, 'min_roc_auc': 0.9, 'max_false_positive_rate': 0.1, 'max_false_positive_rate_benign_path': 0.1, 'max_mean_per_sample_latency_ms': 5.0, 'fpr_tolerance_sigma': 1.96, 'extra': {}}

| Requirement | Threshold | Observed | Result |
|---|---|---|---|
| Recall (phishing caught) | >= 0.8500 | 0.8633 | PASS |
| Precision | >= 0.9000 | 0.9982 | PASS |
| ROC-AUC | >= 0.9000 | 0.9443 | PASS |
| False positive rate (all benign) | <= 0.1561 (+1.96 SE of a 110-row benign sample (+0.0561)) | 0.1091 | PASS |
| False positive rate (benign URLs with a path) | <= 0.1561 (+1.96 SE of a 110-row benign sample (+0.0561)) | 0.0543 | PASS |
| mean_per_sample_latency_ms | <= 5.0000 | 0.0015 | PASS |


### Tier verdicts

| Tier | Meaning | Verdict |
|---|---|---|
| strict | precision-grade: clears the bar for a stage trusted to decide on its own (e.g. letting the prefilter short-circuit the pipeline). | FAIL |
| triage | triage-grade: acceptable for the 15%-weighted prefilter whose verdict is re-checked by every later layer and disclosed in the report. | PASS |

### Probability calibration

Not applied (identity: disabled with --no-calibrate).

### Calibrated vs raw score (same model, same test split)

| Metric | Raw score | Calibrated (served) |
|---|---|---|
| roc_auc | 0.9443 | 0.9443 |
| recall | 0.8633 | 0.8633 |
| precision | 0.9982 | 0.9982 |
| false_positive_rate | 0.1091 | 0.1091 |
| expected_calibration_error | 0.1628 | 0.1628 |

## Zero-day detection

Detection rate on phishing URLs whose registrable domain was never seen in training: **0.8633**

Cutoff: 2026-07-02 21:16:31+00:00 (rows observed at/after it form the test set)
Zeros-day basis: 7849 phishing URLs across 5294 unseen domains, of 7855 test rows
Timestamp coverage: 77893 dated rows (84.9%); 13879 undated rows kept out of the test set
False positives were measured on 110 benign rows (104 of them on a domain also seen in training; --dedup-scope positives)
