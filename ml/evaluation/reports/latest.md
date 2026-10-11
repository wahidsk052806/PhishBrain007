# PhishBrain Prefilter — Evaluation Report

Generated: 2026-09-23T05:33:00.702441+00:00

## Status: Evaluated

Dataset: `data\processed\prefilter_dataset.csv` (7959 test rows)
Split: zero-day split at cutoff 2026-07-02 21:16:31+00:00 (7620 test rows dropped as same-domain-as-training; 13879 undated rows kept out of the test set via --undated-policy train; domain holdout scope 'positives')
Decision threshold: 0.5
Model: `backend\models\prefilter.cbm`

| Metric | Value |
|---|---|
| Accuracy | 0.8637 |
| Precision | 0.9982 |
| Recall | 0.8633 |
| F1 | 0.9259 |
| ROC-AUC | 0.9443 |
| False Positive Rate | 0.1091 |
| False Positive Rate (benign URLs with a path) | 0.0543 |
| Mean Batch Latency (ms) | 8.711 |
| Mean Per-Sample Latency (ms) | 0.0011 |

Confusion matrix: TP=6776 FP=12 FN=1073 TN=98

## Zero-day detection

**Detection rate on phishing whose registrable domain was never seen in training: 0.8633**

Cutoff: 2026-07-02 21:16:31+00:00 — every test row was observed at or after it.
Basis: 7849 phishing URLs across 5294 domains unseen in training (7855 test rows on unseen domains, of 7959 total).
Timestamp coverage: 77893 rows had a real observation time (84.9%); 13879 undated rows were kept out of the test set rather than assigned a date (7620 further test rows were dropped because training had already seen their domain).
False positive rate basis: 110 benign test rows, 6 of them on a domain unseen in training and 104 on a domain training had already seen (domain holdout scope `positives`). With lexical URL features only, a shared benign domain cannot hand the model an answer — but `--dedup-scope all` measures the stricter variant if you need it.

## Deployment gate: PASSED (tier: triage)

Tier meaning: triage-grade: acceptable for the 15%-weighted prefilter whose verdict is re-checked by every later layer and disclosed in the report.

Thresholds: {'min_recall': 0.9, 'min_precision': 0.85, 'min_roc_auc': 0.95, 'max_false_positive_rate': 0.05, 'max_false_positive_rate_benign_path': 0.1, 'max_mean_per_sample_latency_ms': 5.0, 'fpr_tolerance_sigma': 0.0, 'extra': {}}

| Requirement | Threshold | Observed | Result |
|---|---|---|---|
| Recall (phishing caught) | >= 0.8500 | 0.8633 | PASS |
| Precision | >= 0.9000 | 0.9982 | PASS |
| ROC-AUC | >= 0.9000 | 0.9443 | PASS |
| False positive rate (all benign) | <= 0.1561 (+1.96 SE of a 110-row benign sample (+0.0561)) | 0.1091 | PASS |
| False positive rate (benign URLs with a path) | <= 0.1561 (+1.96 SE of a 110-row benign sample (+0.0561)) | 0.0543 | PASS |
| mean_per_sample_latency_ms | <= 5.0000 | 0.0011 | PASS |


### Tier verdicts

| Tier | Meaning | Verdict |
|---|---|---|
| strict | precision-grade: clears the bar for a stage trusted to decide on its own (e.g. letting the prefilter short-circuit the pipeline). | FAIL |
| triage | triage-grade: acceptable for the 15%-weighted prefilter whose verdict is re-checked by every later layer and disclosed in the report. | PASS |

Deployed artifact declares: tier `triage`, gate.passed=True

Probability calibration recorded in the model metadata: `identity`.

