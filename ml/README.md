# AI Phishing Guard: ML Backend

Flask API and model training code for the AI Phishing Guard extension.

## Files

| File | Purpose |
| :--- | :--- |
| `app.py` | REST API: `/predict`, `/health`, `/model-info`, `/api/model-evaluation`, `/test-pages/*` |
| `feature_extractor.py` | Turns a URL into 32 numeric features. Lists come from `shared/config.json` |
| `build_dataset.py` | Builds the training CSV from PhishTank and Tranco |
| `dataset_utils.py` | Loading, cleaning and domain-grouped splitting |
| `train_model.py` | Cross-validated model selection, training, saving |
| `evaluate_model.py` | Held-out evaluation, writes `evaluation_results.json` and the report |
| `domain_intel.py` | Optional domain age and certificate lookups |
| `model/phishing_model.pkl` | Current model package |
| `model/phishing_model_v2_legacy.pkl` | Previous 20-feature model, kept for comparison |
| `tests/` | pytest suite |

## Run

```bash
pip install -r requirements.txt
python ml/app.py
```

| Variable | Default | Meaning |
| :--- | :--- | :--- |
| `AIPHISH_HOST` | `127.0.0.1` | Bind address |
| `AIPHISH_PORT` | `5000` | Port |
| `AIPHISH_MODEL_PATH` | `ml/model/phishing_model.pkl` | Model file |
| `AIPHISH_ENABLE_INTEL` | `0` | Set to `1` to allow domain age and certificate lookups |

## API

### `POST /predict`

```json
{ "url": "https://example.com/login", "intel": false }
```

Returns `prediction`, `phishing_probability`, `legitimate_probability`, `ai_risk_score` (0 to 100), `model`, `feature_count`, `top_features`. When `intel` is true and the backend has intelligence enabled, an `intel` object with `domain_age_days` and `cert` is included. Private and loopback hosts are never looked up.

### `GET /health`

Returns `{"status": "ok", "version": "...", "feature_count": 32, "intel_enabled": false}`.

## Retrain

```bash
python ml/build_dataset.py          # download feeds and write ml/dataset/phishing_urls_full.csv
python ml/train_model.py            # train, evaluate, save
python ml/evaluate_model.py         # evaluate the saved model again
```

`build_dataset.py` options: `--per-class`, `--tranco-depth`, `--seed`, `--phishtank-file`, `--tranco-file`.

### Dataset design

- Phishing rows are real verified URLs from PhishTank.
- Legitimate rows are real Tranco domains. Paths are synthetic: some ordinary templates, and many copied from the *shape* of real phishing URLs with letters and digits randomised so path length and depth cannot separate the classes.
- About 15% of legitimate rows sit on shared hosting platforms, because many ordinary personal sites do. This share is an assumption.
- Splits are grouped by domain. Shared-hosting sites are grouped by full hostname.

### What the numbers mean

The model sees only the URL, and the legitimate class is partly synthetic. Treat the metrics as a comparison between model versions, not as a promise about real-world accuracy.

## Feature set

The feature order is part of the model contract. The API refuses to start if the model's stored feature list differs from `FEATURE_NAMES`. After changing a feature, run `train_model.py`.

## Tests

```bash
python -m pytest ml/tests
```
