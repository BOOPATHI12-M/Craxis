"""Export the input schema of a trained scikit-learn model to JSON.

Use this to learn exactly what a model expects (column names, order, numeric
vs categorical, encoders, imputer and scaler values) without guessing.

IMPORTANT: loading a joblib/pickle file runs code from the file. Only run this
on a model file you created or fully trust, and preferably inside a virtual
environment that has the SAME scikit-learn version the model was trained with
(for the model in ml/model/phishing_model.joblib that is 1.8.0).

Usage:
    python tools/export_model_schema.py ml/model/phishing_model.joblib
    python tools/export_model_schema.py path/to/model.joblib --out schema.json
"""
import argparse
import json
import sys
import warnings
from pathlib import Path


def walk_estimators(obj):
    """Yield (name, estimator) for a Pipeline, unwrapping dict payloads."""
    if isinstance(obj, dict) and "model" in obj:
        obj = obj["model"]
    steps = getattr(obj, "steps", None)
    if steps:
        for name, est in steps:
            yield name, est
    else:
        yield "model", obj


def describe_transformer(name, transformer, columns):
    info = {"name": name, "type": type(transformer).__name__, "columns": list(columns)}
    inner = getattr(transformer, "steps", None)
    if inner:
        info["steps"] = []
        for step_name, step in inner:
            entry = {"name": step_name, "type": type(step).__name__}
            if hasattr(step, "strategy"):
                entry["strategy"] = step.strategy
            if hasattr(step, "statistics_"):
                entry["statistics"] = [None if v != v else float(v) for v in step.statistics_]
            if hasattr(step, "mean_") and step.mean_ is not None:
                entry["mean"] = [float(v) for v in step.mean_]
                entry["scale"] = [float(v) for v in step.scale_]
            if hasattr(step, "categories_"):
                entry["categories"] = [[str(c) for c in cats] for cats in step.categories_]
                entry["handle_unknown"] = getattr(step, "handle_unknown", None)
            info["steps"].append(entry)
    return info


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("model", help="Path to a trusted .joblib or .pkl model file.")
    parser.add_argument("--out", help="Output JSON path (default: <model>.schema.json).")
    args = parser.parse_args()

    import joblib
    import sklearn

    path = Path(args.model)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        payload = joblib.load(path)

    schema = {
        "file": path.name,
        "loaded_with_sklearn": sklearn.__version__,
        "load_warnings": sorted({str(w.message)[:200] for w in caught}),
        "payload_type": type(payload).__name__,
        "payload_keys": sorted(payload.keys()) if isinstance(payload, dict) else None,
        "estimators": [],
    }

    model = payload["model"] if isinstance(payload, dict) and "model" in payload else payload
    schema["input_columns"] = [str(c) for c in getattr(model, "feature_names_in_", [])] or None
    schema["n_features_in"] = int(getattr(model, "n_features_in_", 0)) or None

    for name, est in walk_estimators(payload):
        entry = {"step": name, "type": type(est).__name__}
        if hasattr(est, "transformers_"):
            entry["transformers"] = [
                describe_transformer(t_name, t, cols)
                for t_name, t, cols in est.transformers_
                if t != "drop"
            ]
            entry["remainder"] = str(getattr(est, "remainder", ""))
        if hasattr(est, "n_estimators"):
            entry["n_estimators"] = int(est.n_estimators)
            entry["classes"] = [str(c) for c in getattr(est, "classes_", [])]
            entry["n_features_in"] = int(getattr(est, "n_features_in_", 0))
            entry["max_depth"] = est.max_depth
            entry["class_weight"] = str(est.class_weight)
        schema["estimators"].append(entry)

    out = Path(args.out) if args.out else path.with_suffix(path.suffix + ".schema.json")
    out.write_text(json.dumps(schema, indent=2), encoding="utf-8")
    print(f"Wrote {out}")
    print(f"scikit-learn at load time: {sklearn.__version__}")
    if schema["load_warnings"]:
        print("Warnings while loading:")
        for w in schema["load_warnings"]:
            print("  -", w)
    print(f"Input columns: {len(schema['input_columns'] or [])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
