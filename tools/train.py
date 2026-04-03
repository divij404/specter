"""
Specter — ML Training Pipeline
================================
Loads all session exports, builds a feature matrix, trains an XGBoost
5-class classifier, evaluates it, and exports to ONNX for in-browser
inference via onnxruntime-web.

Classes:  legitimate | fingerprinting | behavioral | ad_network | analytics
session_replay is handled by the rule-based classifier (too few examples).
unclassified records are excluded.

Usage:
    python tools/train.py
    python tools/train.py --exports tools/exports --out extension/data/model.onnx
"""

import json
import glob
import argparse
import os
import numpy as np
from pathlib import Path

from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb
from onnxmltools import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType

# -- Config --------------------------------------------------------------------

FEATURE_COLS = [
    "has_cors_header",
    "has_encoded_params",
    "has_no_cache",
    "has_origin_header",
    "has_referer_header",
    "has_set_cookie",
    "has_tracking_params",
    "is_font_or_style",
    "is_same_domain",
    "is_small_image",
    "is_third_party",
    "is_tiny_response",
    "domain_is_cdn",
    "domain_matches_analytics",
    "domain_matches_session_replay",
    "path_is_tracker",
    "path_matches_ad",
    "path_matches_analytics",
    "path_matches_fingerprint",
    "path_matches_session_replay",
    "in_blocklist",
    "loads_as_script",
    "subdomain_is_tracker",
    "path_depth",
    "query_param_count",
    "tracking_param_count",
    "url_length",
]

# Classes the model handles — session_replay excluded (rule-based fallback)
TRAIN_LABELS = {
    "legitimate",
    "fingerprinting",
    "behavioral",
    "ad_network",
    "analytics",
}

MIN_CONFIDENCE = 0.70   # silver label threshold
MIN_CLASS_SIZE = 20     # drop classes below this after filtering


# -- Data loading --------------------------------------------------------------

def load_exports(exports_dir: str) -> list[dict]:
    pattern = os.path.join(exports_dir, "specter-full-session_*.json")
    files = sorted(glob.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No export files found in {exports_dir}")

    records = []
    for path in files:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        requests = data.get("requests", [])
        records.extend(requests)
        print(f"  {os.path.basename(path)}: {len(requests):,} requests")

    print(f"\nTotal loaded: {len(records):,} requests from {len(files)} sessions")
    return records


def build_feature_matrix(records: list[dict]):
    rows_X, rows_y = [], []
    skipped = {"unclassified": 0, "session_replay": 0, "low_confidence": 0, "missing_feature": 0}

    for r in records:
        label = r.get("category", "")
        conf  = r.get("confidence", 0.0)

        if label == "unclassified":
            skipped["unclassified"] += 1
            continue
        if label == "session_replay":
            skipped["session_replay"] += 1
            continue
        if label not in TRAIN_LABELS:
            continue
        if conf < MIN_CONFIDENCE:
            skipped["low_confidence"] += 1
            continue

        row = []
        missing = False
        for col in FEATURE_COLS:
            val = r.get(col)
            if val is None:
                missing = True
                break
            row.append(float(val))

        if missing:
            skipped["missing_feature"] += 1
            continue

        rows_X.append(row)
        rows_y.append(label)

    print(f"\nSkipped:")
    for reason, count in skipped.items():
        if count:
            print(f"  {reason}: {count:,}")

    X = np.array(rows_X, dtype=np.float32)
    y = np.array(rows_y)
    return X, y


# -- Class balance report -------------------------------------------------------

def print_distribution(y, title="Label distribution"):
    labels, counts = np.unique(y, return_counts=True)
    total = len(y)
    print(f"\n{title}:")
    for label, count in sorted(zip(labels, counts), key=lambda x: -x[1]):
        print(f"  {label:<20} {count:>6,}  ({count/total*100:.1f}%)")


# -- Training ------------------------------------------------------------------

def train(X, y):
    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    n_classes = len(le.classes_)

    print(f"\nClasses: {list(le.classes_)}")

    # Compute per-class weights for imbalance handling
    class_counts = np.bincount(y_enc)
    class_weights = len(y_enc) / (n_classes * class_counts)
    sample_weights = np.array([class_weights[i] for i in y_enc], dtype=np.float32)

    X_train, X_test, y_train, y_test, sw_train, _ = train_test_split(
        X, y_enc, sample_weights,
        test_size=0.20,
        random_state=42,
        stratify=y_enc,
    )

    print(f"\nTrain: {len(X_train):,}  Test: {len(X_test):,}")

    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(
        X_train, y_train,
        sample_weight=sw_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    # -- Evaluation ------------------------------------------------------------
    y_pred = model.predict(X_test)
    y_pred_labels = le.inverse_transform(y_pred)
    y_test_labels = le.inverse_transform(y_test)

    print("\n-- Classification Report ---------------------------------------")
    print(classification_report(y_test_labels, y_pred_labels, digits=3))

    print("-- Confusion Matrix ---------------------------------------------")
    classes = le.classes_
    cm = confusion_matrix(y_test_labels, y_pred_labels, labels=classes)
    header = f"{'':>20}" + "".join(f"{c[:8]:>10}" for c in classes)
    print(header)
    for i, row_label in enumerate(classes):
        row = f"{row_label:<20}" + "".join(f"{v:>10}" for v in cm[i])
        print(row)

    print("\n-- Feature Importances (top 15) ---------------------------------")
    importances = model.feature_importances_
    ranked = sorted(zip(FEATURE_COLS, importances), key=lambda x: -x[1])
    for feat, imp in ranked[:15]:
        bar = "#" * int(imp * 200)
        print(f"  {feat:<35} {imp:.4f}  {bar}")

    return model, le


# -- ONNX export ---------------------------------------------------------------

def export_json_for_extension(model, le, json_path: str, labels_path: str):
    """Save XGBoost JSON for service_worker.js and aligned label arrays.

    Embeds `specter_labels` (class names in LabelEncoder order) in the JSON so
    inference never relies on a stale committed model_labels.json. Also writes
    labels_path as a plain array for tooling and backward compatibility.
    """
    os.makedirs(os.path.dirname(json_path) or ".", exist_ok=True)
    model.save_model(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    labels = list(le.classes_)
    payload["specter_labels"] = labels
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f)

    os.makedirs(os.path.dirname(labels_path) or ".", exist_ok=True)
    with open(labels_path, "w", encoding="utf-8") as f:
        json.dump(labels, f)
    print(f"Extension JSON saved -> {json_path}")
    print(f"Label list saved   -> {labels_path}  ({len(labels)} classes)")


def export_onnx(model, le, out_path: str):
    n_features = len(FEATURE_COLS)
    initial_type = [("float_input", FloatTensorType([None, n_features]))]

    onnx_model = convert_xgboost(model, initial_types=initial_type)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    size_kb = os.path.getsize(out_path) / 1024
    print(f"\nONNX model saved -> {out_path}  ({size_kb:.1f} KB)")

    # Save label map alongside the model so the extension knows class indices
    label_map_path = out_path.replace(".onnx", "_labels.json")
    with open(label_map_path, "w") as f:
        json.dump(list(le.classes_), f)
    print(f"Label map saved  -> {label_map_path}")


# -- Main ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Train Specter request classifier")
    parser.add_argument("--exports", default="tools/exports",  help="Path to exports directory")
    parser.add_argument("--out",     default="extension/data/model.onnx", help="Output ONNX path")
    parser.add_argument(
        "--json-out",
        default="extension/data/model.json",
        help="XGBoost JSON model path for the extension (includes specter_labels)",
    )
    parser.add_argument(
        "--labels-out",
        default="extension/data/model_labels.json",
        help="Plain JSON array of class names (same order as --json-out)",
    )
    parser.add_argument("--no-onnx", action="store_true", help="Skip ONNX export (eval only)")
    parser.add_argument("--no-json", action="store_true", help="Skip extension JSON + label export")
    args = parser.parse_args()

    print("-- Loading exports ----------------------------------------------")
    records = load_exports(args.exports)

    print("\n-- Building feature matrix --------------------------------------")
    X, y = build_feature_matrix(records)
    print(f"Feature matrix: {X.shape[0]:,} rows × {X.shape[1]} features")

    print_distribution(y, "Silver label distribution")

    # Drop any class with fewer than MIN_CLASS_SIZE examples
    labels, counts = np.unique(y, return_counts=True)
    dropped = [l for l, c in zip(labels, counts) if c < MIN_CLASS_SIZE]
    if dropped:
        print(f"\nDropping under-represented classes: {dropped}")
        mask = np.isin(y, dropped, invert=True)
        X, y = X[mask], y[mask]
        print_distribution(y, "After dropping")

    print("\n-- Training -----------------------------------------------------")
    model, le = train(X, y)

    if not args.no_json:
        print("\n-- Exporting extension JSON + labels ---------------------------")
        export_json_for_extension(model, le, args.json_out, args.labels_out)

    if not args.no_onnx:
        print("\n-- Exporting to ONNX --------------------------------------------")
        export_onnx(model, le, args.out)

    print("\nDone.")


if __name__ == "__main__":
    main()
