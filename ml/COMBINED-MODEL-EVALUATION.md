# Combined-Data Model Evaluation

**Decision: keep v3 as the active model.** The best combined variant, `combined weighted`, is a real compromise but not a clear win. It improves on real browsing URLs and on newer phishing, it regresses on v3's own held-out set and on shared hosting, and the independent homepage test still fails for every model.

## 1. What was trained

Training data is v3's original training split plus the PhreshPhish training split. Sites in either test or eval split are never used for training.

| Variant | Rows | Phishing rows | Construction | Time |
| :--- | ---: | ---: | :--- | ---: |
| `candidate_combined_concat` | 287,527 | 90,584 | All rows of both sources | 17 s |
| `candidate_combined_weighted` | 287,527 | 90,584 | Same rows. Original rows weighted about 10.6 times so each source counts equally | 15 s |
| `candidate_combined_balanced` | 115,274 | 57,988 | Original rows plus the class-balanced PhreshPhish subset | 9 s |

Same algorithm (Random Forest, 150 trees), settings and 32-feature extractor as v3. Files are git-ignored. The active model hash is unchanged.

## 2. Results

Threshold 0.5. Recall at 1% FPR is the share of phishing caught when only 1% of legitimate rows may be flagged.

### 2.1 PhreshPhish eval sites (66,319 rows, never used for training anything)

| Model | ROC-AUC | Precision | Recall | False-positive rate | Recall at 1% FPR |
| :--- | ---: | ---: | ---: | ---: | ---: |
| v3 (active) | 0.776 | 0.656 | 0.609 | 0.137 | 0.359 |
| PhreshPhish only | 0.974 | 0.913 | 0.879 | 0.036 | 0.815 |
| Combined concat | **0.974** | 0.924 | 0.870 | 0.031 | **0.817** |
| Combined weighted | 0.970 | **0.945** | 0.833 | **0.021** | 0.792 |
| Combined balanced | 0.952 | 0.900 | 0.854 | 0.041 | 0.768 |

### 2.2 v3's original held-out set (5,294 rows, synthetic legitimate paths)

| Model | ROC-AUC | Precision | Recall | False-positive rate | Recall at 1% FPR |
| :--- | ---: | ---: | ---: | ---: | ---: |
| v3 (active) | **0.924** | **0.906** | 0.655 | **0.052** | **0.459** |
| PhreshPhish only | 0.699 | 0.568 | 0.670 | 0.391 | 0.185 |
| Combined concat | 0.792 | 0.706 | 0.704 | 0.225 | 0.289 |
| Combined weighted | 0.847 | 0.818 | 0.687 | 0.117 | 0.393 |
| Combined balanced | 0.864 | 0.793 | 0.683 | 0.136 | 0.367 |

### 2.3 Independent homepages (StealthPhisher, 50,000 rows, no shared site or URL with any training or eval set)

| Model | ROC-AUC | False-positive rate | Recall |
| :--- | ---: | ---: | ---: |
| v3 (active) | 0.498 | 0.997 | 0.828 |
| PhreshPhish only | 0.688 | 1.000 | 0.954 |
| Combined concat | 0.496 | 1.000 | 0.935 |
| Combined weighted | 0.411 | 1.000 | 0.907 |
| Combined balanced | 0.302 | 1.000 | 0.895 |

Every model flags essentially all of these legitimate homepages. Combining the data did not fix this, and it lowered the AUC below chance for two variants.

### 2.4 Recall on newer phishing (19,733 PhishTank URLs absent from every training and eval set)

| Model | Detected | On shared hosting | Not on shared hosting |
| :--- | ---: | ---: | ---: |
| v3 (active) | 78.9% | 92.0% | 63.4% |
| PhreshPhish only | 88.1% | 100.0% | 74.0% |
| Combined concat | 88.0% | 99.6% | 74.2% |
| Combined weighted | 84.2% | 97.4% | 68.5% |
| Combined balanced | 85.0% | 97.7% | 70.1% |

### 2.5 Legitimate sites on shared hosting (the known weak spot)

| Model | Real benign sites flagged (77 rows) | Synthetic benign sites flagged (475 rows) |
| :--- | ---: | ---: |
| v3 (active) | 64.9% | **18.7%** |
| PhreshPhish only | 87.0% | 99.4% |
| Combined concat | 81.8% | 51.2% |
| Combined weighted | 74.0% | 30.3% |
| Combined balanced | 88.3% | 35.4% |

### 2.6 Targeted checks on PhreshPhish eval sites

| Group | Rows | v3 | PhreshPhish only | Combined concat | Combined weighted | Combined balanced |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Benign, deep path (wrongly flagged) | 30,944 | 14.6% | 1.2% | 1.1% | **0.7%** | 4.1% |
| Benign, root only (wrongly flagged) | 5,108 | 9.5% | 13.9% | 11.3% | 7.9% | **3.8%** |
| Benign, no `www.` (wrongly flagged) | 20,012 | 16.9% | 7.3% | 6.2% | **4.2%** | 6.5% |
| Phishing, not shared hosting (detected) | 13,490 | 49.7% | 82.3% | **81.2%** | 76.5% | 79.1% |
| Phishing, shared hosting (detected) | 6,355 | 84.8% | 99.7% | 99.4% | 97.6% | 98.7% |

## 3. How to read this

| Question | Answer |
| :--- | :--- |
| Is `combined weighted` better than v3 on real-looking pages? | **Yes**, clearly: false-positive rate 2.1% against 13.7%, and deep-path benign pages wrongly flagged 0.7% against 14.6% |
| Does it catch more recent phishing? | Yes: 84.2% against 78.9%. Part of this comes from calling nearly all shared-hosting sites phishing |
| Does it keep v3's performance on v3's own test? | **No.** AUC 0.847 against 0.924 and false-positive rate 11.7% against 5.2% |
| Is it safer for legitimate shared-hosting sites? | **No.** 30% of synthetic and 74% of real ones are flagged, against 19% and 65% for v3 |
| Does it generalise to an unrelated source? | **No.** Same failure as every other model |
| Does combining fix the PhreshPhish-only candidate's weaknesses? | Partly. v3-test AUC rises from 0.70 to 0.85, and shared-hosting flags fall from 99% to 30%, at little cost on PhreshPhish |

The weighting variant is the best trade-off. Concatenating without weights lets the larger source dominate. The balanced variant discards most rows and does worst on the independent set.

## 4. What these numbers cannot show

- Both main sources are the data the models were built from. Neither is verified ground truth for the browsing you do.
- The independent homepage set is itself imperfect: its legitimate side is mostly obscure domains with unverified labels, and every model fails it, so it measures nothing about relative quality.
- Real benign shared-hosting data is only 77 rows.
- Choosing a "best" variant on these same sets would overstate its quality. All five were reported and none was tuned on the independent sets.

## 5. Regression checks

| Check | Result |
| :--- | :--- |
| Active model hash | Unchanged (`d84c6bbd...`) |
| Existing tests | Unchanged files, rerun below |
| Backend contract | Candidates load through `AIPHISH_MODEL_PATH` and return the same fields |

## 6. Recommendation

1. **Keep v3 active.** The combined model is not a clear improvement, and the shared-hosting regression would unfairly flag legitimate personal sites.
2. **Keep `candidate_combined_weighted` as the best candidate** for the next round of testing.
3. **The deciding evidence is missing.** It needs a benign sample that reflects what you really browse, with your consent, and a verified legitimate shared-hosting sample.
4. **If a model is promoted later**, do it behind a switch, keep v3 as fallback, and re-run the browser tests.

## 7. Files added

| File | Purpose |
| :--- | :--- |
| `ml/train_combined.py` | Trains the three combined variants. Refuses to overwrite |
| `ml/compare_combined.py` | Evaluates all models on the same data |
| `ml/combined_comparison_results.json` | Full numbers |
| `ml/model/candidate_combined_*.pkl` | Candidates, git-ignored |
