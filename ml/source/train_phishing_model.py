from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
)


# --------------------------------------------------
# 1. Find and load the dataset
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

DATASET_PATH = BASE_DIR / "StealthPhisher2025.csv"
MODEL_PATH = BASE_DIR / "phishing_model.joblib"

if not DATASET_PATH.exists():
    raise FileNotFoundError(
        f"Dataset not found: {DATASET_PATH}"
    )

print("Loading dataset...")

df = pd.read_csv(DATASET_PATH)

# Clean accidental spaces in column names.
df.columns = df.columns.str.strip()

print("Dataset shape:", df.shape)
print("\nOriginal label counts:")
print(df["Label"].value_counts(dropna=False))


# --------------------------------------------------
# 2. Clean the labels
# --------------------------------------------------

df["Label"] = df["Label"].astype("string").str.strip()

df = df[
    df["Label"].isin(["Phishing", "Legitimate"])
].copy()

df = df.dropna(subset=["URL", "Label"])

# Remove exact duplicate URLs.
df = df.drop_duplicates(subset=["URL"])

# Convert the target into two classes.
df["Label"] = df["Label"].map({
    "Legitimate": 0,
    "Phishing": 1,
})

print("\nCleaned dataset shape:", df.shape)
print("\nCleaned label counts:")
print(df["Label"].value_counts())


# --------------------------------------------------
# 3. Prepare the input features
# --------------------------------------------------

# URL and Domain are excluded because the dataset already
# contains engineered URL/domain features. Excluding them
# also reduces direct memorisation of individual domains.

excluded_columns = ["URL", "Domain", "Label"]

feature_columns = [
    column
    for column in df.columns
    if column not in excluded_columns
]

X = df[feature_columns].copy()
y = df["Label"]

# TLD is categorical. Other features should be numeric.
categorical_columns = (
    ["TLD"] if "TLD" in X.columns else []
)

numeric_columns = [
    column
    for column in X.columns
    if column not in categorical_columns
]

# Convert numeric feature columns safely.
for column in numeric_columns:
    X[column] = pd.to_numeric(
        X[column],
        errors="coerce",
    )

print("\nNumber of input features:", len(feature_columns))


# --------------------------------------------------
# 4. Split training and testing data
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print("\nTraining records:", len(X_train))
print("Testing records:", len(X_test))


# --------------------------------------------------
# 5. Build preprocessing steps
# --------------------------------------------------

numeric_pipeline = Pipeline([
    (
        "imputer",
        SimpleImputer(strategy="median"),
    ),
    (
        "scaler",
        StandardScaler(),
    ),
])

transformers = [
    (
        "numeric",
        numeric_pipeline,
        numeric_columns,
    )
]

if categorical_columns:
    categorical_pipeline = Pipeline([
        (
            "imputer",
            SimpleImputer(strategy="most_frequent"),
        ),
        (
            "encoder",
            OneHotEncoder(handle_unknown="ignore"),
        ),
    ])

    transformers.append(
        (
            "categorical",
            categorical_pipeline,
            categorical_columns,
        )
    )

preprocessor = ColumnTransformer(
    transformers=transformers,
)


# --------------------------------------------------
# 6. Create the machine-learning model
# --------------------------------------------------

model = Pipeline([
    ("preprocessor", preprocessor),
    (
        "classifier",
        RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=42,
            n_jobs=-1,
        ),
    ),
])


# --------------------------------------------------
# 7. Train the model
# --------------------------------------------------

print("\nTraining model...")

model.fit(X_train, y_train)

print("Training completed.")


# --------------------------------------------------
# 8. Evaluate on the held-out test set
# --------------------------------------------------

print("\nEvaluating model...")

predictions = model.predict(X_test)

print(
    "\nAccuracy:",
    round(accuracy_score(y_test, predictions), 4),
)

print("\nClassification report:")

print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Legitimate", "Phishing"],
        zero_division=0,
    )
)

print("\nConfusion matrix:")
print(
    confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1],
    )
)


# --------------------------------------------------
# 9. Save the trained model and feature information
# --------------------------------------------------

joblib.dump(
    {
        "model": model,
        "feature_columns": feature_columns,
        "categorical_columns": categorical_columns,
        "numeric_columns": numeric_columns,
        "label_mapping": {
            0: "Legitimate",
            1: "Phishing",
        },
    },
    MODEL_PATH,
)

print("\nModel saved successfully:")
print(MODEL_PATH)