# Craxis: Model Evaluation Report

## Summary

- **Algorithm:** Random Forest
- **Model version:** 3.0
- **Dataset:** `phishing_urls_full.csv` (30000 unique URLs)
- **Method:** 80/20 split grouped by domain, so no site is in both sets
- **Generated:** 2026-10-15

## Held-out metrics

| Metric | Value |
| :--- | ---: |
| Accuracy | 0.8207 |
| Precision | 0.9055 |
| Recall | 0.6551 |
| F1 score | 0.7602 |
| ROC-AUC | 0.9237 |
| False-positive rate | 0.0524 |
| Recall at 1% false-positive rate | 0.4586 |

## Confusion matrix

| | Predicted legitimate | Predicted phishing |
| :--- | ---: | ---: |
| **Actual legitimate** | 2841 | 157 |
| **Actual phishing** | 792 | 1504 |

## Samples

| Class | Whole dataset | Test split |
| :--- | ---: | ---: |
| Legitimate | 15000 | 2998 |
| Phishing | 15000 | 2296 |

## Model comparison (5-fold grouped cross-validation)

| Model | Mean ROC-AUC | Std |
| :--- | ---: | ---: |
| Random Forest | 0.8478 | 0.0641 |
| Histogram Gradient Boosting | 0.8275 | 0.0848 |

## Comparison with the previous model

| Metric | Previous (20 features) | Current |
| :--- | ---: | ---: |
| Accuracy | 0.5892 | 0.8207 |
| Recall | 0.5000 | 0.6551 |
| ROC-AUC | 0.6398 | 0.9237 |
| False-positive rate | 0.3426 | 0.0524 |

## Top features

1. `hostname_length`: 15.4%
2. `hostname_entropy`: 13.4%
3. `path_length`: 9.3%
4. `url_length`: 9.0%
5. `site_label_length`: 7.4%
6. `digit_count`: 6.2%
7. `site_label_vowel_ratio`: 5.2%
8. `path_depth`: 4.2%

## Limitations

1. Phishing URLs come from one public feed (PhishTank). Other feeds may behave differently.
2. Legitimate URLs use real Tranco domains with synthetic paths, so real-world deep links may score differently.
3. Phishing patterns change quickly. Retrain on fresh data regularly.
4. The model sees only URL features. Page content is scored separately by the extension.
