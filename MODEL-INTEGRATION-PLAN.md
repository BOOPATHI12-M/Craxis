# New Model Integration Plan

Plan for adding the Random Forest model trained on the second laptop (`ml/model/phishing_model.joblib`) to Craxis without breaking the existing extension.

**Status:** inspection finished. No integration code has been written and no model has been connected.

---

## 1. What was found

### 1.1 The new model file (`phishing_model.joblib`, 6.6 MB)

Read statically with `pickletools`. The file was **not loaded**, so none of its code ran.

| Item | Finding |
| :--- | :--- |
| Container | joblib file holding a dict with the key `model` |
| Contents | scikit-learn `Pipeline`: `ColumnTransformer` followed by `RandomForestClassifier` |
| Trained with | scikit-learn **1.8.0** |
| Numeric columns (61) | `SimpleImputer(strategy="median")` then `StandardScaler` |
| Categorical column (1) | `TLD`, `SimpleImputer(most_frequent)` then `OneHotEncoder(handle_unknown="ignore")` |
| Total inputs | 62 named columns (61 numeric + `TLD`), matching your description |
| Preprocessing inside the model | **Yes.** Raw values go in, scaling and encoding happen inside |
| Input type | Must be a table with these exact column names, not a bare array |

### 1.2 The 62 inputs, in stored order

**URL text (22).** Computable from the URL string if the original definition is known:
`LengthOfURL`, `URLComplexity`, `CharacterComplexity`, `DomainLengthOfURL`, `IsDomainIP`, `TLDLength`, `LetterCntInURL`, `URLLetterRatio`, `DigitCntInURL`, `URLDigitRatio`, `EqualCharCntInURL`, `QuesMarkCntInURL`, `AmpCharCntInURL`, `OtherSpclCharCntInURL`, `URLOtherSpclCharRatio`, `NumberOfHashtags`, `NumberOfSubdomains`, `HavingPath`, `PathLength`, `HavingQuery`, `HavingFragment`, `HavingAnchor`

**Connection (1).** `HasSSL` (scheme or real certificate, definition unknown)

**Needs the fetched page or network response (30).**
`IsUnreachable`, `LineOfCode`, `LongestLineLength`, `HasTitle`, `HasFavicon`, `HasRobotsBlocked`, `IsResponsive`, `IsURLRedirects`, `IsSelfRedirects`, `HasDescription`, `HasPopup`, `HasIFrame`, `IsFormSubmitExternal`, `HasSocialMediaPage`, `HasSubmitButton`, `HasHiddenFields`, `HasPasswordFields`, `HasBankingKey`, `HasPaymentKey`, `HasCryptoKey`, `HasCopyrightInfoKey`, `CntImages`, `CntFilesCSS`, `CntFilesJS`, `CntSelfHRef`, `CntEmptyRef`, `CntExternalRef`, `CntPopup`, `CntIFrame`, `UniqueFeatureCnt`

**Definition not recoverable from the model (8).**
`WAPLegitimate`, `WAPPhishing`, `ShannonEntropy`, `FractalDimension`, `KolmogorovComplexity`, `HexPatternCnt`, `Base64PatternCnt`, `LikelinessIndex`

**Categorical (1).** `TLD`

The model stores column names, not their formulas. The formulas live in the feature-generation code that built your CSV.

### 1.3 Compatibility with the current project

| Check | Result |
| :--- | :--- |
| Feature count | 62 expected, 32 produced by `feature_extractor.py` |
| Name overlap | **None.** No current feature name matches a new one |
| Feature order | Different. Current code returns a plain list, the new model needs named columns |
| Calculable at prediction time | **No.** 30 inputs need the page, and 8 have unknown definitions |
| Current API input | Only `{"url": ...}`. Page data is not sent to the backend today |
| scikit-learn version | New model 1.8.0, project pins 1.9 or newer |

**Verdict: incompatible as it stands.** Connecting it now would require passing invented values, which this plan forbids.

### 1.4 Problems found in the project itself

These are separate from the new model but block safe testing.

| Problem | Evidence | Effect |
| :--- | :--- | :--- |
| `ml/model/phishing_model.pkl` is corrupted | 16.9 MB of bytes containing UTF-8 replacement characters, zlib error on load | Backend will not start. 10 Python tests error |
| `phishing_model_v2_legacy.pkl` is missing | File not present | The comparison backup is gone |
| The v3 model that was trained earlier was never committed | `git` only holds the original 140 KB v2 model | Needs a retrain or a restore from git |

The `.pkl` looks like it was overwritten through a text editor or a text-mode copy. Binary model files must be copied as binary.

---

## 2. Phases

Each phase has a gate. Do not start the next phase until the gate passes.

### Phase 0: Restore a working baseline

**Goal:** a running backend and a backup, before touching anything new.

1. Keep `phishing_model.joblib` untouched. Record its SHA-256 hash.
2. Restore a working model in `ml/model/`:
   - **Option A (recommended):** `python ml/train_model.py`. Rebuilds the version 3.0 model from the existing dataset in about two minutes and refreshes the evaluation files.
   - **Option B:** `git checkout -- ml/model/phishing_model.pkl`. Restores the original version 2 model, which has the 20-feature schema and will fail the feature-count check in the current API.
3. Copy the restored file to `ml/model/backup/phishing_model_v3.pkl` using a binary copy.
4. Add `*.pkl` and `*.joblib` to `.gitattributes` as `binary` so editors and git do not alter them.

**Gate:** `python -m pytest ml/tests` shows all 36 tests passing and `python ml/app.py` starts.

### Phase 1: Collect the originals from the second laptop

**Goal:** get the facts that cannot be recovered from the model file.

Bring these files. None of them is guessed at here.

| Needed | Why |
| :--- | :--- |
| Feature-generation code for all 62 columns | The only source of the formulas for the 8 unknown features and the exact rules for the page features |
| `train_model.py` as used | Split method, random seed, class balance, hyperparameters |
| CSV header and the first 200 rows (not the whole file) | Value ranges, types, example URLs, how `TLD` was written |
| Original evaluation output | To compare against, not to trust |
| `pip freeze` of that laptop | Exact scikit-learn and numpy versions |
| Dataset source and licence | Legal use and what the labels mean |
| How the 336,749 records were collected and when | Pages change. Old crawls may not reflect today |

Then run, on the second laptop or in a virtual environment with scikit-learn 1.8.0:

```bash
python tools/export_model_schema.py ml/model/phishing_model.joblib
```

This writes a JSON file with the exact input columns, medians, scaler values, the TLD categories and the forest settings. Only run it on a file you trust, because loading a pickle runs code.

**Gate:** you have the generation code, and the schema JSON lists exactly 62 columns.

### Phase 2: Verify the schema

**Goal:** prove what the model expects, with no integration yet.

1. Create a throwaway virtual environment with `scikit-learn==1.8.0` and load the joblib file there.
2. Compare `feature_names_in_` with section 1.2 name by name and order by order.
3. Check the TLD categories, and confirm unknown TLDs are ignored rather than rejected.
4. Feed it 20 rows from the original CSV and confirm the prediction matches the original CSV label output.
5. Record the schema hash (SHA-256 of the ordered column list) for the API to check later.
6. Decide the version question: run the model on scikit-learn 1.8.0 in its own environment, or retrain it on 1.9 from the original CSV. Do not rely on cross-version unpickling.

**Gate:** all 62 columns confirmed, round-trip predictions match, and a version decision is made.

### Phase 3: Build a matching feature extractor

**Goal:** produce each of the 62 values exactly as the training data did.

Create `ml/features_phiusiil.py` (name to be confirmed from the source code) as a **new file**. Do not edit `feature_extractor.py`.

1. **URL features (22 + TLD).** Port the original code. Add a test per feature with hand-computed expected values.
2. **Page features (30).** Choose one source and document it:

| Option | Pros | Risks |
| :--- | :--- | :--- |
| A. Backend downloads the page | Same method as training, works without the extension | Server-side request to arbitrary URLs. Needs private-address blocking (already in `domain_intel.py`), timeouts, size limits. Sends the URL off the browser. Slow. Many phishing pages are already offline |
| B. Extension sends measured values from the rendered page | Fast, no extra fetch, user's own view | The rendered DOM is not the raw HTML used in training, so counts such as `LineOfCode` can shift. Needs every definition reproduced in `content.js` |
| C. URL-only model | Fully computable now | Needs a new training run on the URL columns only |

3. **Unknown features (8).** Implement only from the original code. If a definition cannot be obtained, the model cannot be used as is.
4. **Missing values.** The built-in median imputer must **not** be used to hide missing page data. 30 features filled with medians would produce a confident but meaningless score.

**Gate:** for 100 sample rows, the new extractor reproduces the original CSV values (exact for integers, a stated tolerance for floats), and a feature-order test passes.

### Phase 4: Integrate behind the existing API

**Goal:** add the model without changing what the extension depends on.

- Add a model registry in `ml/app.py`. Environment variable `AIPHISH_MODEL` selects `v3` (default) or the new model. The v3 model and its tests stay in place.
- Keep `POST /predict` input `{"url": ...}`. Add an **optional** `page_features` object for option B. Old callers keep working.
- Validate before predicting: exact column set, numeric types, finite values, schema hash. Reject anything else.
- Extend the response without removing any current field:

```json
{
  "status": "ok",
  "prediction": "PHISHING",
  "phishing_probability": 0.87,
  "legitimate_probability": 0.13,
  "ai_risk_score": 87.0,
  "model": {
    "name": "Random Forest",
    "version": "4.0",
    "feature_count": 62,
    "schema_hash": "..."
  },
  "disclaimer": "Statistical estimate. Not proof that a site is malicious."
}
```

- When the model cannot score, return `status: "unavailable"` with a `reason`, and **no** `prediction`, `phishing_probability` or `ai_risk_score`. HTTP 200 for "model cannot score this input" and 4xx or 5xx for bad requests and server faults. The extension already treats a missing result as "AI unavailable", not as safe.
- `shared/api.js` change: read `status`, and keep accepting the old response shape.
- `shared/scoring.js` stays as is. The score fusion, URL rules and page checks are not touched.

**Gate:** with the new model switched off, all existing tests and the browser test still pass unchanged.

### Phase 5: Testing

| Area | Test |
| :--- | :--- |
| Startup | Backend starts, loads the model, `/health` reports version and `feature_count: 62` |
| Schema | Column count is 62, order matches the stored schema, schema hash matches |
| Features | One unit test per feature against hand-computed values |
| Legitimate examples | A fixed list of well-known sites. Expect low probability. Report misses, do not tune the list to pass |
| Phishing examples | Only safe, authorised data: URLs taken from the labelled test CSV and documented test strings. Never visit or fetch live phishing sites |
| Bad input | Missing `url`, empty, non-string, too long, wrong types in `page_features`, NaN, extra keys |
| Unavailable | Model file missing, schema mismatch, page features absent: response is `unavailable`, never SAFE |
| Backend down | Extension keeps working with URL and page rules, popup shows the offline notice |
| Compatibility | Old `{"url": ...}` request still returns every old field |
| Regression | `python -m pytest ml/tests`, `npm test`, `npm run test:e2e` |

**Gate:** every row above passes, and the report lists the commands and counts that actually ran.

### Phase 6: Honest evaluation

**Goal:** decide whether the new model is better, not just different.

- Evaluate on a split **grouped by domain**, not a random row split. A random split over 336,749 rows usually places the same site in train and test, which inflates results.
- Check the dataset for duplicate and near-duplicate URLs and for labels derived from the features themselves.
- Compare against the v3 model on the same held-out URLs.
- Report ROC-AUC, recall at a fixed false-positive rate (1%), and the false-positive rate on a list of known-good sites.
- State the crawl date. Page features age quickly.
- Only promote the new model to default if it beats v3 on held-out, domain-grouped data and works with the inputs the extension can really provide.

**Gate:** a written comparison. Promotion is your decision.

### Phase 7: Rollout and report

1. Keep the v3 model as the fallback for at least one release.
2. Update `README.md`, `ml/README.md`, `extension.md`, `CHANGELOG.md`.
3. Give the final report with: files changed and why, tests that passed with counts, start commands, and how to reload and test the extension.

Commands that will be reported (current, valid today):

```bash
pip install -r requirements.txt
python ml/app.py
```

Reload the extension: `chrome://extensions`, find Craxis, press the reload icon, then open `http://127.0.0.1:5000/test-pages/index.html`.

---

## 3. Decisions needed from you

| # | Question | Why it matters |
| :--- | :--- | :--- |
| 1 | Can you supply the feature-generation code and training script? | Without them 8 features cannot be reproduced and the model cannot be used as is |
| 2 | Page features: backend fetch (A), extension-measured (B) or URL-only retrain (C)? | Decides the privacy model, the API change and the effort |
| 3 | Run on scikit-learn 1.8.0 or retrain on 1.9? | Cross-version unpickling is unsupported |
| 4 | Restore the working model with a retrain (Option A) or from git (Option B)? | Needed before any testing |
| 5 | Is the CSV licensed for use here, and when was it crawled? | Legal use and how much to trust page features |

## 4. Risks

| Risk | Mitigation |
| :--- | :--- |
| Unpickling a model file executes code | Only load files you created, in an isolated environment. The inspection so far used static reading only |
| Training and prediction features differ | Feature-by-feature tests against original CSV rows |
| High reported accuracy that does not hold in use | Domain-grouped evaluation and a fresh independent sample |
| Backend fetching pages is a server-side request risk | Option A needs address filtering, redirects limits and size caps. Option B and C avoid it |
| Missing page data silently imputed | Explicit `unavailable` status. No median filling |
| Model is shown as proof | Fixed disclaimer, scores shown as estimates, no wording that claims a site is malicious |

## 5. Files this plan will touch (when approved)

| File | Change |
| :--- | :--- |
| `ml/features_phiusiil.py` | New. Matching feature extractor |
| `ml/app.py` | Model registry, validation, extended response, `unavailable` status |
| `shared/api.js` | Read `status`, keep old shape working |
| `content.js` | Only for option B: measure page features |
| `ml/tests/` | New tests for features, schema and API |
| `ml/model/` | Restore working model, add `backup/` |
| `.gitattributes` | Mark model files as binary |
| Docs | `README.md`, `ml/README.md`, `extension.md`, `CHANGELOG.md` |

Files that stay unchanged: `shared/scoring.js`, `background.js`, the popup, warning, history and dashboard pages, and `ml/feature_extractor.py`.
