# Phase 1 and 2 Findings: StealthPhisher2025 Model

Results of inspecting the files in `ml/source/` against the integration plan. No project code, API or extension file was changed by this work.

## 1. Verdict

**Do not connect this model yet.** Three separate reasons, each enough on its own.

| # | Reason | Evidence |
| :--- | :--- | :--- |
| 1 | The inputs cannot be reproduced at prediction time | 30 page features and 8 features with unknown formulas. The generation code was not in the supplied files |
| 2 | The dataset has a construction shortcut, so its accuracy is not real-world accuracy | Section 4 |
| 3 | The model fails on independent URLs | Section 5 |

## 2. What was supplied

| File | Notes |
| :--- | :--- |
| `train_phishing_model.py` | The training script. It matches the saved model exactly |
| `StealthPhisher2025.csv` | 336,749 rows, 65 columns, 93 MB |
| `phishing_model.joblib` | Identical (same SHA-256) to `ml/model/phishing_model.joblib` |

**Not supplied:** the code that turned each URL and page into the 62 feature values. The training script only reads the finished CSV. That code is the missing piece.

## 3. Confirmed facts (Task 2)

| Question | Answer |
| :--- | :--- |
| Feature count and order | 62 inputs. The order is the CSV column order after removing `URL`, `Domain`, `Label`. It matches the order read from the model file |
| Types | 61 numeric, 1 categorical (`TLD`). Numeric cells are converted with `to_numeric`, no cell failed to convert |
| Categorical encoding | `TLD` uses most-frequent imputation then one-hot encoding with unknown values ignored. The data has 3,865 distinct TLD values |
| Preprocessing inside the model | Yes. Median imputer and standard scaler for numbers, one-hot for `TLD`, then the forest |
| Forest settings | 100 trees, max depth 20, min 2 samples per leaf, balanced subsample class weights, seed 42 |
| Labels | Phishing 175,806 and Legitimate 160,943 (52% phishing). No duplicate URLs, no missing numeric values, 2 missing `TLD` |
| Column quirk | `HasCopyrightInfoKey` has a trailing space in the CSV header. The training script strips it, so the saved model uses the clean name |
| `TLD` quirk | 17,337 rows have a value that is not a TLD (for IP URLs it is the last octet or `118:8090`). A matching extractor must copy this behaviour |
| Split used | Random 80/20, stratified, not grouped by domain |
| Calculable at prediction time | See section 3.1 |

### 3.1 Can each feature be calculated?

URL text features were tested against the real CSV values on a random sample of 30,000 rows.

| Feature | Rule tested | Match | Status |
| :--- | :--- | ---: | :--- |
| `Domain` | `urlparse(url).netloc` | 100.00% | Reproducible |
| `DigitCntInURL` | count digits | 100.00% | Reproducible |
| `EqualCharCntInURL` | count `=` | 100.00% | Reproducible |
| `QuesMarkCntInURL` | count `?` | 100.00% | Reproducible |
| `IsDomainIP` | IPv4 hostname | 99.99% | Reproducible |
| `HasSSL` | URL starts with `https://` | 99.97% | Reproducible, but a scheme check only |
| `TLD`, `TLDLength` | `Domain.split(".")[-1]` | 99.96% | Reproducible |
| `URLDigitRatio` | digits / length, 3 decimals | 99.90% | Reproducible |
| `HavingFragment` | fragment present | 99.66% | Near |
| `PathLength` | `len(path)` | 99.52% | Near |
| `HavingQuery` | query present | 99.51% | Near |
| `LengthOfURL` | `len(url)` | 99.49% | Near |
| `DomainLengthOfURL` | `len(Domain)` | 99.77% | Near |
| `NumberOfHashtags` | count `#` | 97.19% | Near |
| `AmpCharCntInURL` | count `&` | 97.15% | Near |
| `NumberOfSubdomains` | dots in hostname minus 1 | 97.41% | Near, rule unclear |
| `CharacterComplexity` | `1 / len(netloc + path)` | 95.55% | Partial |
| `OtherSpclCharCntInURL` | best of 3 rules tried | 41.29% | **Not reproduced** |
| `URLOtherSpclCharRatio` | depends on the above | 3.16% | **Not reproduced** |
| `HavingPath` | path not empty | 83.01% | **Not reproduced** |
| `HavingAnchor` | `#` in URL | 80.34% | **Not reproduced** |
| `LetterCntInURL`, `URLLetterRatio` | count letters | 0.00% | **Not reproduced** |
| `URLComplexity` | three rules tried | under 1% | **Not reproduced** |
| 30 page features | need the fetched page | n/a | **Cannot be reproduced from a URL** |
| `ShannonEntropy` | URL and domain tried | 0.00% | **Not reproduced** (probably computed on the page) |
| 7 other computed features | `WAP*`, `FractalDimension`, `KolmogorovComplexity`, `HexPatternCnt`, `Base64PatternCnt`, `LikelinessIndex` | n/a | **Unknown formula** |

A "near" match below 100% means the original code treats some URLs differently, for example whitespace, encoding or odd characters. Without the original code those edge cases cannot be settled.

**Result:** of the 23 URL-text columns (including `TLD`), 7 reproduce almost exactly, 9 are close and 7 do not. `HasSSL` is a simple scheme check. None of the 38 page or computed features can be built from a URL.

## 4. Why the reported accuracy cannot be trusted

Training the same pipeline on this CSV with scikit-learn 1.9.1 and a grouped split:

| Model inputs | Split | ROC-AUC | False-positive rate | Recall |
| :--- | :--- | ---: | ---: | ---: |
| All 62 (their model) | random (theirs) | 0.9997 | 0.34% | 99.7% |
| All 62 | grouped by domain | 0.9998 | 0.27% | 99.5% |
| URL text and TLD only (23) | grouped by domain | 0.9985 | 0.13% | 93.2% |
| 30 page features only | grouped by domain | 0.9983 | 0.68% | 94.4% |

Grouping by domain barely changes the result, so domain leakage is not the main cause. The cause is how the classes were built:

| Property | Legitimate | Phishing |
| :--- | ---: | ---: |
| URLs with a path (`HavingPath`) | 6.6% | 81.4% |
| Median path length | 0 | 3 |
| `HasSSL` | 100% | 71.1% |
| Median URL length | 28 | 37 |

The legitimate class is almost entirely home pages such as `https://example.com`. A model that learns "has a path means phishing" scores about 99%. Real legitimate pages usually have paths, such as `github.com/user/repo` or `bank.com/account/login`.

## 5. Independent check

The model's URL-reproducible subset (15 features) was trained on StealthPhisher2025 and then tested on a separate set of 30,000 URLs: 15,000 current PhishTank URLs and 15,000 Tranco domains with realistic paths.

| Metric | Result |
| :--- | ---: |
| ROC-AUC | 0.73 |
| False-positive rate at 0.5 | 99.5% |
| Recall | 98.3% |

At the default threshold it labels almost every URL with a path as phishing. This test is deliberately hard on the path shortcut, so it overstates the problem for ordinary browsing, but it shows the model's accuracy depends on the dataset's construction and not on real phishing signals.

**Limits of this check:** the legitimate paths in the independent set are synthetic, only the 15 reproducible features were used, and the crawl dates differ. The result is a warning sign, not a final measurement.

## 6. Other items

- **Retraining on scikit-learn 1.9.1 works.** The same script reproduces the pipeline, so version 1.8.0 pickles do not have to be loaded.
- **Loading the `.joblib` was avoided.** Everything above came from static inspection and a fresh retrain, so no unpickled code ran.
- **Page features age.** `IsUnreachable` is 9.8% for legitimate and 3.7% for phishing rows, which reflects crawl timing, not website behaviour.

## 7. Options from here

| Option | What it means | Verdict |
| :--- | :--- | :--- |
| A. Connect the model as is | Needs 38 features that cannot be built | Not possible |
| B. Find the original generator | The dataset is public. Check its publication page for the crawler and feature code. If it exists, port it and re-run the checks | Needed before any further work |
| C. Retrain a URL-only model on this CSV | Feasible, but it inherits the path shortcut and fails the independent check | Not recommended without fixing the data |
| D. Use this CSV to improve the current model | Take only its real legitimate hostnames and its phishing URLs, rebuild the legitimate class with realistic paths, keep current features | Feasible and the safest use |
| E. Keep the current model (v3) | Honest held-out ROC-AUC 0.92, fully reproducible | Current default |

**Recommendation:** keep v3 as the active model, ask where the feature-generation code came from (option B), and consider option D to enlarge the training data. Do not use the new model's published numbers in any claim about accuracy.

## 8. What changed in the project

| Change | Reason |
| :--- | :--- |
| `.gitignore` | Keeps the 93 MB CSV and duplicate `.joblib` out of git |
| This file | Records the findings |

No change was made to `ml/app.py`, `feature_extractor.py`, `shared/`, `background.js` or any test.
