"""Dataset helpers shared by training and evaluation."""
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

from feature_extractor import CONFIG, registrable_domain

ML_DIR = Path(__file__).resolve().parent
DATASET_DIR = ML_DIR / "dataset"
FULL_DATASET = DATASET_DIR / "phishing_urls_full.csv"
SAMPLE_DATASET = DATASET_DIR / "phishing_urls.csv"

SPLIT_SEED = 42
TEST_FRACTION = 0.20

_SHARED = list(CONFIG["shared_hosting_suffixes"])


def group_key(url: str) -> str:
    """Group key used so the same site never appears in both train and test.

    Pages on shared hosting (github.io, netlify.app, ...) are grouped by full
    hostname, because the registrable domain would lump unrelated sites together.
    """
    try:
        host = (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        host = ""
    if not host:
        return url
    for suffix in _SHARED:
        if host == suffix or host.endswith("." + suffix):
            return host
    return registrable_domain(host)


def resolve_dataset_path(explicit: str = None) -> Path:
    """Pick the dataset: explicit path, else the full dataset, else the small sample."""
    if explicit:
        return Path(explicit)
    if FULL_DATASET.exists():
        return FULL_DATASET
    return SAMPLE_DATASET


def load_dataset(path: Path) -> pd.DataFrame:
    """Load, clean and de-duplicate a url,label CSV. Adds a 'group' column."""
    df = pd.read_csv(path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns.")
    df = df.dropna(subset=["url", "label"]).copy()
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"] != ""]
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)
    bad = sorted(set(df["label"].unique()) - {0, 1})
    if bad:
        raise ValueError(f"Invalid labels found: {bad}")
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    df["group"] = df["url"].map(group_key)
    return df


def group_split(df: pd.DataFrame):
    """Deterministic group-aware train/test split. Returns (train_idx, test_idx)."""
    from sklearn.model_selection import GroupShuffleSplit

    if df["group"].nunique() < 5 or len(df) < 20:
        # Tiny datasets cannot be split by group; fall back to a stratified split.
        from sklearn.model_selection import train_test_split

        idx = list(range(len(df)))
        train_idx, test_idx = train_test_split(
            idx, test_size=TEST_FRACTION, random_state=SPLIT_SEED, stratify=df["label"]
        )
        return sorted(train_idx), sorted(test_idx)

    splitter = GroupShuffleSplit(n_splits=1, test_size=TEST_FRACTION, random_state=SPLIT_SEED)
    train_idx, test_idx = next(splitter.split(df, df["label"], groups=df["group"]))
    return list(train_idx), list(test_idx)
