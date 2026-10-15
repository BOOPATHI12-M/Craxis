"""Write ml/model/feature_baselines.json.

Holds, for every model feature, the median value on legitimate and on phishing
URLs of the TRAINING split. The API uses it to explain a single website's AI
score (see explain.py). It does not touch any model or dataset.

Usage:
    python ml/build_feature_baselines.py
"""
import datetime
import json
import sys

import numpy as np

from dataset_utils import FULL_DATASET, ML_DIR, SAMPLE_DATASET, group_split, load_dataset
from feature_extractor import FEATURE_NAMES, extract_features

OUT = ML_DIR / "model" / "feature_baselines.json"


def main() -> int:
    source = FULL_DATASET if FULL_DATASET.exists() else SAMPLE_DATASET
    df = load_dataset(source)
    train_idx, _ = group_split(df)
    train = df.iloc[train_idx]
    X = np.array([extract_features(u) for u in train["url"]], dtype=float)
    y = train["label"].to_numpy()
    if (y == 0).sum() == 0 or (y == 1).sum() == 0:
        print("Both classes are needed.", file=sys.stderr)
        return 1

    data = {
        "feature_names": list(FEATURE_NAMES),
        "legit_median": [round(float(v), 4) for v in np.median(X[y == 0], axis=0)],
        "phishing_median": [round(float(v), 4) for v in np.median(X[y == 1], axis=0)],
        "rows_legitimate": int((y == 0).sum()),
        "rows_phishing": int((y == 1).sum()),
        "source": f"median of the training split of {source.name}",
        "generated_on": datetime.date.today().isoformat(),
    }
    OUT.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Wrote {OUT} ({data['rows_legitimate']} legitimate and {data['rows_phishing']} phishing rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
