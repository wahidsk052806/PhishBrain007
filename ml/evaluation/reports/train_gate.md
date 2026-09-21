# PhishBrain Prefilter — Training Gate

Generated: 2026-09-21T19:48:27.548297+00:00

Dataset: `data\processed\prefilter_dataset.csv` (train 67016 / test 7959 rows)
Split: time-ordered zero-day split at cutoff 2026-07-02 21:16:31+00:00 (7620 test rows dropped as same-domain-as-training)
Model written to: `backend\models\prefilter.cbm`

## Deployment gate: FAILED

Thresholds: {'min_recall': 0.9, 'min_precision': 0.85, 'min_roc_auc': 0.95, 'max_false_positive_rate': 0.05, 'max_false_positive_rate_benign_path': 0.1, 'max_mean_per_sample_latency_ms': 5.0, 'extra': {}}

| Requirement | Threshold | Observed | Result |
|---|---|---|---|
| Recall (phishing caught) | >= 0.9000 | 0.8633 | FAIL |
| Precision | >= 0.8500 | 0.9982 | PASS |
| ROC-AUC | >= 0.9500 | 0.9443 | FAIL |
| False positive rate (all benign) | <= 0.0500 | 0.1091 | FAIL |
| False positive rate (benign URLs with a path) | <= 0.1000 | 0.0543 | PASS |
| mean_per_sample_latency_ms | <= 5.0000 | 0.0016 | PASS |

**Model rejected — not deployed.** Reasons:

- Recall (phishing caught): 0.8633 (required >= 0.9000)
- ROC-AUC: 0.9443 (required >= 0.9500)
- False positive rate (all benign): 0.1091 (required <= 0.0500)

## Zero-day detection

Detection rate on phishing URLs whose registrable domain was never seen in training: **0.8633**

Cutoff: 2026-07-02 21:16:31+00:00 (rows observed at/after it form the test set)
Zeros-day basis: 7849 phishing URLs across 5294 unseen domains, of 7855 test rows
Timestamp coverage: 77893 dated rows (84.9%); 13879 undated rows kept out of the test set
False positives were measured on 110 benign rows (104 of them on a domain also seen in training; --dedup-scope positives)
