# Candidate Model Evaluation (Phases 4 to 6)

**Decision: keep v3 as the active model.** The candidates win on data that looks like their own training source, lose on v3's own held-out set, and no model generalises to a third independent source. Improvement is not demonstrated.

## 1. What was trained

| Model | File | Training rows | Time |
| :--- | :--- | ---: | ---: |
| v3 (active, unchanged) | `ml/model/phishing_model.pkl` | 24,706 | n/a |
| Candidate all | `ml/model/candidate_phresh_all.pkl` | 262,821 | 9 s |
| Candidate balanced | `ml/model/candidate_phresh_balanced.pkl` | 90,568 | 2 s |

- Same algorithm and settings as v3: Random Forest, 150 trees, `min_samples_leaf=2`, balanced class weights.
- Same unchanged 32-feature extractor and feature order.
- Feature extraction took 209 s once and was cached outside the project. Total wall time was about 4 minutes.
- Both candidates load in the unchanged Flask backend through `AIPHISH_MODEL_PATH`, and return the same response fields. Bad input still returns HTTP 400.
- The candidate files are 59 MB and 32 MB and are git-ignored.

## 2. Results on the same held-out data

Threshold 0.5 unless stated.

### 2.1 New eval sites (66,319 rows, sites never used to train v3 or any candidate)

| Model | ROC-AUC | Precision | Recall | False-positive rate | Recall at 1% FPR |
| :--- | ---: | ---: | ---: | ---: | ---: |
| v3 | 0.776 | 0.656 | 0.609 | 0.137 | 0.359 |
| Candidate all | **0.974** | 0.913 | 0.879 | 0.036 | 0.815 |
| Candidate balanced | 0.953 | 0.894 | 0.868 | 0.044 | 0.782 |

### 2.2 Balanced eval subset (22,752 rows, equal classes and matched path shape)

| Model | ROC-AUC | Precision | Recall | False-positive rate |
| :--- | ---: | ---: | ---: | ---: |
| v3 | 0.780 | 0.795 | 0.547 | 0.141 |
| Candidate all | 0.918 | 0.884 | 0.820 | 0.108 |
| Candidate balanced | **0.946** | 0.931 | 0.834 | 0.062 |

### 2.3 v3's own held-out set (5,294 rows, synthetic legitimate paths)

| Model | ROC-AUC | Precision | Recall | False-positive rate |
| :--- | ---: | ---: | ---: | ---: |
| v3 | **0.924** | 0.906 | 0.655 | 0.052 |
| Candidate all | 0.699 | 0.568 | 0.670 | 0.391 |
| Candidate balanced | 0.754 | 0.609 | 0.660 | 0.324 |

### 2.4 Independent third source (StealthPhisher, never used by any model)

50,000 rows, 49,997 sites, balanced, root-only URLs with no query. All sites and URLs used by any training or eval set were removed first.

| Model | ROC-AUC | False-positive rate | Recall |
| :--- | ---: | ---: | ---: |
| v3 | 0.498 | 0.997 | 0.828 |
| Candidate all | 0.688 | 1.000 | 0.954 |
| Candidate balanced | 0.417 | 1.000 | 0.921 |

Every model labels almost all of these legitimate home pages as phishing. None has any useful ranking ability at the threshold used.

### 2.5 Recall on newer phishing (19,733 PhishTank URLs from today's feed, none in any training or eval set)

| Model | Detected, raw URL | Detected, query stripped | On shared hosting | Not shared hosting |
| :--- | ---: | ---: | ---: | ---: |
| v3 | 80.4% | 78.9% | 92.0% | 63.4% |
| Candidate all | 89.1% | 88.1% | 100.0% | 74.0% |
| Candidate balanced | 87.3% | 86.3% | 100.0% | 70.0% |

Only recall can be measured here, because the set holds phishing only.

## 3. Targeted checks on the new eval sites

Benign rows show the percentage wrongly flagged. Phishing rows show the percentage detected.

| Group | Rows | v3 | Candidate all | Candidate balanced |
| :--- | ---: | ---: | ---: | ---: |
| Benign, deep path (2+ segments) | 30,944 | 14.6% flagged | **1.2%** | 4.3% |
| Benign, any path | 41,366 | 14.2% | **2.3%** | 4.5% |
| Benign, root only | 5,108 | 9.5% | 13.9% | **4.0%** |
| Benign, starts with `www.` | 26,462 | 11.2% | **0.7%** | 2.6% |
| Benign, no `www.` | 20,012 | 16.9% | 7.3% | 6.8% |
| Benign, on shared hosting | 77 | 64.9% | **87.0%** | **98.7%** |
| Phishing, shared hosting | 6,355 | 84.8% detected | 99.7% | 100.0% |
| Phishing, not shared hosting | 13,490 | 49.7% | **82.3%** | 80.5% |
| Phishing, with path | 8,579 | 47.1% | 77.3% | 79.8% |
| Phishing, root only | 11,266 | 71.5% | 95.9% | 92.1% |

## 4. Leakage and sanity controls

| Control | Result | Meaning |
| :--- | ---: | :--- |
| Shuffled training labels, tested on eval sites | ROC-AUC 0.498 | The pipeline does not leak labels |
| Candidate trained without `path_length` and `path_depth` | ROC-AUC 0.970 vs 0.974 | The skill does not come from path length |
| Sites shared between train and eval | 0 | Verified in the dataset report |
| URL overlap with current dataset | 0 | Verified |
| Candidate-balanced result on independent data | AUC 0.417, below chance | Learned patterns that are specific to the source, not general phishing signals |

## 5. What the results mean

| Finding | Evidence |
| :--- | :--- |
| On real browsing URLs v3 is weak | It wrongly flags 14.6% of real benign deep-path pages and has a 13.7% false-positive rate on the new eval sites |
| The candidate is much better on that kind of data | False flags on deep-path benign pages fall from 14.6% to 1.2% |
| The candidate is not better on v3's own data | AUC 0.70 against 0.92. v3's legitimate class is synthetic, so this partly measures that artificial data |
| The candidate is worse for legitimate shared-hosting sites | 87% to 99% flagged, from only 77 rows. It treats a hosting platform as a phishing signal |
| No model generalises to a different source | All three fail on the StealthPhisher home-page test |

Each model scores best on data resembling its own training source. Neither source is verified ground truth, so neither set of numbers can be treated as real-world accuracy.

## 6. Regression tests (Phase 6)

| Check | Result |
| :--- | :--- |
| Active model hash before and after | Identical (`d84c6bbd...`) |
| Python tests | 36 passed |
| JavaScript tests | 23 passed |
| Browser test, TC01 to TC10 | 10 of 10 passed |
| Browser test, block, trust and settings flows | 17 of 17 passed |
| `/predict` response fields | Unchanged. Candidates return the same fields |
| Warning and scoring behaviour | Unchanged, since no extension file was touched |
| v3 fallback | Still the default. Candidates load only when `AIPHISH_MODEL_PATH` is set |

## 7. Recommendation

1. **Keep v3 as the active model.** Improvement is not demonstrated across sources.
2. **Do not promote either candidate.** The shared-hosting behaviour would wrongly flag legitimate personal sites, and independent generalisation failed.
3. **Treat `candidate_phresh_all` as promising** for reducing false alarms on ordinary pages with paths. In the extension one layer alone cannot block, since the AI contributes at most half of the score, so a model that is wrong in one layer is limited in effect.
4. **Next evidence needed:**
   - A benign sample you collect yourself (your own browsing history, with your consent) to measure the real false-positive rate on pages you actually visit.
   - A test on phishing and benign URLs from a source neither model has seen, with verified labels.
   - A fix for the shared-hosting problem, for example more legitimate shared-hosting examples from a verified source.
5. **Possible low-risk step:** a combined model trained on both the original and the new data, evaluated on all three sources above.

## 8. Files added

| File | Purpose |
| :--- | :--- |
| `ml/train_candidate.py` | Trains the two candidates under new names. Refuses to overwrite |
| `ml/compare_models.py` | Read-only comparison on identical data |
| `ml/model_comparison_results.json` | Full numbers |
| `ml/model/candidate_phresh_all.pkl`, `candidate_phresh_balanced.pkl` | Candidates (git-ignored) |
| `.gitignore` | Two new lines |
