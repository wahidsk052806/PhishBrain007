# PhishBrain Prefilter — Evaluation Report

Generated: 2026-09-20T09:47:45.327445+00:00

## Status: Evaluated

Dataset: `data\processed\prefilter_dataset.csv` (7962 test rows)
Split: zero-day split at cutoff 2026-07-02 20:24:16+00:00 (7615 test rows dropped as same-domain-as-training; 13879 undated rows kept out of the test set via --undated-policy train; domain holdout scope 'positives')
Decision threshold: 0.5
Model: `backend\models\prefilter.cbm`

| Metric | Value |
|---|---|
| Accuracy | 0.9207 |
| Precision | 0.9975 |
| Recall | 0.9220 |
| F1 | 0.9583 |
| ROC-AUC | 0.9399 |
| False Positive Rate | 0.1782 |
| False Positive Rate (benign URLs with a path) | 0.0952 |
| Mean Batch Latency (ms) | 6.416 |
| Mean Per-Sample Latency (ms) | 0.0008 |

Confusion matrix: TP=7248 FP=18 FN=613 TN=83

## Zero-day detection

**Detection rate on phishing whose registrable domain was never seen in training: 0.9220**

Cutoff: 2026-07-02 20:24:16+00:00 — every test row was observed at or after it.
Basis: 7861 phishing URLs across 5297 domains unseen in training (7861 test rows on unseen domains, of 7962 total).
Timestamp coverage: 77883 rows had a real observation time (84.9%); 13879 undated rows were kept out of the test set rather than assigned a date (7615 further test rows were dropped because training had already seen their domain).
False positive rate basis: 101 benign test rows, 0 of them on a domain unseen in training and 101 on a domain training had already seen (domain holdout scope `positives`). With lexical URL features only, a shared benign domain cannot hand the model an answer — but `--dedup-scope all` measures the stricter variant if you need it.

## Deployment gate: FAILED

Thresholds: {'min_recall': 0.9, 'min_precision': 0.85, 'min_roc_auc': 0.95, 'max_false_positive_rate': 0.05, 'max_false_positive_rate_benign_path': 0.1, 'max_mean_per_sample_latency_ms': 5.0, 'extra': {}}

| Requirement | Threshold | Observed | Result |
|---|---|---|---|
| Recall (phishing caught) | >= 0.9000 | 0.9220 | PASS |
| Precision | >= 0.8500 | 0.9975 | PASS |
| ROC-AUC | >= 0.9500 | 0.9399 | FAIL |
| False positive rate (all benign) | <= 0.0500 | 0.1782 | FAIL |
| False positive rate (benign URLs with a path) | <= 0.1000 | 0.0952 | PASS |
| mean_per_sample_latency_ms | <= 5.0000 | 0.0008 | PASS |

**Model rejected — not deployed.** Reasons:

- ROC-AUC: 0.9399 (required >= 0.9500)
- False positive rate (all benign): 0.1782 (required <= 0.0500)

