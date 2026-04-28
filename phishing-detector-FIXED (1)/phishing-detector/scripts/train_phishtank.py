#!/usr/bin/env python3
"""
train_phishtank.py — Phishing Attack Detection Master
======================================================
Complete pipeline to:
  1. Load the PhishTank CSV dataset
  2. Download a legitimate URL source (Majestic Million top sites)
  3. Extract all 10 features from every raw URL
  4. Balance, clean and split the dataset
  5. Train the neural network
  6. Evaluate with accuracy, precision, recall, F1, ROC-AUC
  7. Export the model to TensorFlow.js format
  8. Print the exact constants you need to paste into background.js

Usage:
  python train_phishtank.py --phishtank online-valid.csv

Requirements:
  pip install tensorflow scikit-learn pandas tensorflowjs matplotlib seaborn requests tldextract

Author: Capstone Cybersecurity Project
"""

import argparse
import os
import re
import json
import time
import socket
import requests
import zipfile
import io

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import tldextract
import tensorflow as tf

from urllib.parse              import urlparse
from sklearn.model_selection   import train_test_split, StratifiedKFold
from sklearn.preprocessing     import MinMaxScaler
from sklearn.metrics           import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, classification_report,
    roc_curve, auc,
)
try:
    import tensorflowjs as tfjs
    TFJS_AVAILABLE = True
except ImportError:
    TFJS_AVAILABLE = False
    print("[Warning] tensorflowjs unavailable (uvloop is not supported on Windows).")
    print("          Training will complete and save a Keras .h5 model.")
    print("          Convert later with: tensorflowjs_converter --input_format keras keras_model.h5 ./tfjs_model/")

# ─── Reproducibility ──────────────────────────────────────────────────────────
RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)
tf.random.set_seed(RANDOM_SEED)

# ─── Config ───────────────────────────────────────────────────────────────────
FEATURE_COLUMNS = [
    "url_length",
    "dot_count",
    "has_at",
    "is_https",
    "subdomain_count",
    "is_ip_address",
    "suspicious_tld",
    "form_action_mismatch",   # always 0 for URL-only features
    "has_password_field",     # always 0 for URL-only features
    "external_script_count",  # always 0 for URL-only features
]

# Suspicious TLDs — from APWG / PhishTank trend reports
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work",
    "date", "racing", "review", "win", "bid", "stream", "gdn",
    "link", "click", "loan", "download", "accountant", "science",
    "men", "trade", "webcam", "faith", "party", "rocks",
}

# ─── Feature Extraction ───────────────────────────────────────────────────────

def is_ip_address(hostname: str) -> bool:
    """Return True if hostname is a raw IPv4 or IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET, hostname)
        return True
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, hostname)
        return True
    except socket.error:
        pass
    return False


def count_subdomains(hostname: str) -> int:
    """
    Count subdomains using tldextract for accurate registered-domain splitting.
    e.g.  secure.login.mybank.com  →  subdomain='secure.login'  →  count=2
    """
    ext = tldextract.extract(hostname)
    if not ext.subdomain:
        return 0
    return len(ext.subdomain.split("."))


def has_suspicious_tld(hostname: str) -> bool:
    ext = tldextract.extract(hostname)
    return ext.suffix.lower() in SUSPICIOUS_TLDS


def extract_features(raw_url: str) -> dict:
    """
    Extract the 10-feature vector from a single raw URL string.
    Features that require live page inspection (form_action_mismatch,
    has_password_field, external_script_count) are set to 0 for offline
    training — they are populated at runtime by content.js in the extension.
    """
    features = {
        "url_length":            0,
        "dot_count":             0,
        "has_at":                0,
        "is_https":              0,
        "subdomain_count":       0,
        "is_ip_address":         0,
        "suspicious_tld":        0,
        "form_action_mismatch":  0,   # populated live by content.js
        "has_password_field":    0,   # populated live by content.js
        "external_script_count": 0,   # populated live by content.js
    }

    try:
        raw_url = raw_url.strip()
        features["url_length"] = len(raw_url)
        features["has_at"]     = 1 if "@" in raw_url else 0

        parsed = urlparse(raw_url)
        hostname = parsed.hostname or ""

        features["is_https"]        = 1 if parsed.scheme == "https" else 0
        features["dot_count"]       = hostname.count(".")
        features["subdomain_count"] = count_subdomains(hostname)
        features["is_ip_address"]   = 1 if is_ip_address(hostname) else 0
        features["suspicious_tld"]  = 1 if has_suspicious_tld(hostname) else 0

    except Exception:
        pass  # Return default (zeroed) features for malformed URLs

    return features


# ─── Legitimate URL Source ─────────────────────────────────────────────────────

def download_majestic_million(n: int = 50_000) -> list[str]:
    """
    Download the Majestic Million (top 1M legitimate websites) and
    convert the top-N domains into https:// URLs for use as negative examples.
    This is a free, publicly available dataset with no registration required.
    """
    print(f"\n[Legit URLs] Downloading Majestic Million top sites...")
    url = "https://downloads.majestic.com/majestic_million.csv"
    try:
        resp = requests.get(url, timeout=60, stream=True)
        resp.raise_for_status()
        df   = pd.read_csv(io.StringIO(resp.text), usecols=["Domain"])
        domains = df["Domain"].dropna().head(n).tolist()
        legit_urls = [f"https://www.{d}" for d in domains]
        print(f"[Legit URLs] Downloaded {len(legit_urls):,} legitimate URLs.")
        return legit_urls
    except Exception as e:
        print(f"[Legit URLs] Download failed ({e}). Using built-in fallback list.")
        return _builtin_legit_urls()


def _builtin_legit_urls() -> list[str]:
    """
    Fallback: a hand-curated list of well-known legitimate domains.
    Used only if the Majestic Million download fails.
    """
    domains = [
        "google.com", "youtube.com", "facebook.com", "twitter.com",
        "instagram.com", "linkedin.com", "amazon.com", "wikipedia.org",
        "reddit.com", "netflix.com", "github.com", "stackoverflow.com",
        "microsoft.com", "apple.com", "adobe.com", "dropbox.com",
        "spotify.com", "paypal.com", "ebay.com", "yahoo.com",
        "bing.com", "twitch.tv", "discord.com", "slack.com",
        "zoom.us", "shopify.com", "wordpress.com", "medium.com",
        "nytimes.com", "bbc.com", "cnn.com", "theguardian.com",
        "harvard.edu", "mit.edu", "stanford.edu", "coursera.org",
        "udemy.com", "khanacademy.org", "who.int", "un.org",
    ]
    urls = []
    for d in domains:
        for sub in ["www", "mail", "login", "account", "secure", "app"]:
            urls.append(f"https://{sub}.{d}")
    return urls * 50  # repeat to reach a larger count


# ─── Dataset Loading ──────────────────────────────────────────────────────────

def load_phishtank(csv_path: str) -> pd.DataFrame:
    """
    Load the PhishTank CSV file.

    PhishTank CSV columns (as of 2024):
      phish_id, url, phish_detail_url, submission_time,
      verified, verification_time, online, target

    We use the 'url' column and assign label = 1 (phishing).
    We optionally filter to 'verified = yes' for higher quality.
    """
    print(f"\n[PhishTank] Loading dataset from: {csv_path}")
    try:
        df = pd.read_csv(csv_path, encoding="utf-8", on_bad_lines="skip")
    except TypeError:
        # Older pandas
        df = pd.read_csv(csv_path, encoding="utf-8", error_bad_lines=False)

    print(f"[PhishTank] Raw rows loaded: {len(df):,}")
    print(f"[PhishTank] Columns found: {list(df.columns)}")

    # Normalise column names
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    # PhishTank format detection
    if "url" in df.columns:
        url_col = "url"
    elif "phish_detail_url" in df.columns:
        url_col = "phish_detail_url"
    else:
        # Try first column
        url_col = df.columns[0]

    print(f"[PhishTank] Using URL column: '{url_col}'")
    urls = df[url_col].dropna().astype(str).tolist()

    # Filter: verified phishing only (if column exists)
    if "verified" in df.columns:
        verified = df["verified"].str.lower().isin(["yes", "y", "true", "1"])
        urls_verified = df.loc[verified, url_col].dropna().astype(str).tolist()
        if len(urls_verified) >= 1000:
            urls = urls_verified
            print(f"[PhishTank] Filtered to verified-only: {len(urls):,} URLs")
        else:
            print(f"[PhishTank] Not enough verified entries ({len(urls_verified)}), using all.")

    print(f"[PhishTank] Final phishing URLs: {len(urls):,}")
    return pd.DataFrame({"url": urls, "label": 1})


# ─── Feature Extraction Pipeline ─────────────────────────────────────────────

def build_feature_dataframe(phish_df: pd.DataFrame, legit_urls: list[str]) -> pd.DataFrame:
    """
    Extract features for all phishing AND legitimate URLs and combine them.
    Shows a progress indicator every 5,000 rows.
    """
    legit_df = pd.DataFrame({"url": legit_urls, "label": 0})

    # Balance classes: equal number of phishing and legitimate
    n = min(len(phish_df), len(legit_df))
    phish_df = phish_df.sample(n, random_state=RANDOM_SEED).reset_index(drop=True)
    legit_df = legit_df.sample(n, random_state=RANDOM_SEED).reset_index(drop=True)

    combined = pd.concat([phish_df, legit_df]).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    total = len(combined)

    print(f"\n[Features] Extracting features from {total:,} URLs...")
    print(f"           ({n:,} phishing + {n:,} legitimate)")

    feature_rows = []
    t0 = time.time()

    for i, row in combined.iterrows():
        feats = extract_features(row["url"])
        feats["label"] = int(row["label"])
        feature_rows.append(feats)

        if (i + 1) % 5000 == 0 or (i + 1) == total:
            elapsed = time.time() - t0
            rate    = (i + 1) / elapsed
            eta     = (total - i - 1) / rate if rate > 0 else 0
            print(f"  Progress: {i+1:,}/{total:,}  |  "
                  f"{rate:.0f} URLs/sec  |  ETA: {eta:.0f}s", end="\r")

    print(f"\n[Features] Extraction complete in {time.time()-t0:.1f}s")
    result = pd.DataFrame(feature_rows)
    return result


# ─── Model ────────────────────────────────────────────────────────────────────

def build_model(input_dim: int) -> tf.keras.Model:
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(input_dim,), name="features"),
        tf.keras.layers.Dense(32, activation="relu", name="hidden1",
                              kernel_regularizer=tf.keras.regularizers.l2(1e-4)),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.Dense(16, activation="relu", name="hidden2",
                              kernel_regularizer=tf.keras.regularizers.l2(1e-4)),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(8, activation="relu", name="hidden3"),
        tf.keras.layers.Dense(1, activation="sigmoid", name="output"),
    ], name="PhishingDetector_PhishTank")

    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            tf.keras.metrics.AUC(name="auc"),
            tf.keras.metrics.Precision(name="precision"),
            tf.keras.metrics.Recall(name="recall"),
        ],
    )
    return model


# ─── Evaluation ───────────────────────────────────────────────────────────────

def evaluate_model(model, X_test, y_test, output_dir, threshold=0.5):
    y_prob = model.predict(X_test, verbose=0).ravel()
    y_pred = (y_prob >= threshold).astype(int)

    acc  = accuracy_score (y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec  = recall_score   (y_test, y_pred)
    f1   = f1_score       (y_test, y_pred)
    auc_ = roc_auc_score  (y_test, y_prob)

    print("\n" + "═" * 55)
    print("  PHISHTANK MODEL EVALUATION RESULTS")
    print("═" * 55)
    print(f"  Accuracy   : {acc  * 100:.2f}%")
    print(f"  Precision  : {prec * 100:.2f}%")
    print(f"  Recall     : {rec  * 100:.2f}%")
    print(f"  F1 Score   : {f1   * 100:.2f}%")
    print(f"  ROC-AUC    : {auc_:.4f}")
    print("═" * 55)
    print(classification_report(y_test, y_pred,
                                target_names=["Legitimate", "Phishing"]))

    # ── Confusion Matrix ──────────────────────────────────────────────────
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt="d", cmap="Reds",
                xticklabels=["Legit", "Phishing"],
                yticklabels=["Legit", "Phishing"],
                ax=axes[0])
    axes[0].set_title("Confusion Matrix")
    axes[0].set_ylabel("True Label")
    axes[0].set_xlabel("Predicted Label")

    # ── ROC Curve ─────────────────────────────────────────────────────────
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    roc_auc_val = auc(fpr, tpr)
    axes[1].plot(fpr, tpr, color="crimson", lw=2,
                 label=f"ROC Curve (AUC = {roc_auc_val:.3f})")
    axes[1].plot([0, 1], [0, 1], color="navy", lw=1, linestyle="--")
    axes[1].set_xlim([0.0, 1.0])
    axes[1].set_ylim([0.0, 1.05])
    axes[1].set_xlabel("False Positive Rate")
    axes[1].set_ylabel("True Positive Rate")
    axes[1].set_title("Receiver Operating Characteristic")
    axes[1].legend(loc="lower right")

    plt.tight_layout()
    path = os.path.join(output_dir, "evaluation_plots.png")
    plt.savefig(path, dpi=150)
    print(f"\n  Plots saved → {path}")

    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "auc": auc_}


def plot_training_history(history, output_dir):
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))

    axes[0].plot(history.history["accuracy"],     label="Train", color="steelblue")
    axes[0].plot(history.history["val_accuracy"], label="Val",   color="crimson")
    axes[0].set_title("Accuracy per Epoch")
    axes[0].set_xlabel("Epoch"); axes[0].set_ylabel("Accuracy")
    axes[0].legend(); axes[0].grid(alpha=0.3)

    axes[1].plot(history.history["loss"],     label="Train", color="steelblue")
    axes[1].plot(history.history["val_loss"], label="Val",   color="crimson")
    axes[1].set_title("Loss per Epoch")
    axes[1].set_xlabel("Epoch"); axes[1].set_ylabel("Binary Cross-Entropy")
    axes[1].legend(); axes[1].grid(alpha=0.3)

    plt.tight_layout()
    path = os.path.join(output_dir, "training_history.png")
    plt.savefig(path, dpi=150)
    print(f"  Training history → {path}")


# ─── Normalisation Export ──────────────────────────────────────────────────────

def export_normalisation_params(scaler: MinMaxScaler, output_dir: str):
    params = {
        "feature_names": FEATURE_COLUMNS,
        "feature_mins":  scaler.data_min_.tolist(),
        "feature_maxs":  scaler.data_max_.tolist(),
    }
    path = os.path.join(output_dir, "normalisation_params.json")
    with open(path, "w") as f:
        json.dump(params, f, indent=2)

    print("\n" + "═" * 55)
    print("  COPY THESE INTO src/background.js")
    print("═" * 55)
    print(f"  const FEATURE_MINS = {params['feature_mins']};")
    print(f"  const FEATURE_MAXS = {params['feature_maxs']};")
    print("═" * 55)
    print(f"\n  Full params saved → {path}")


# ─── Save Processed Dataset ───────────────────────────────────────────────────

def save_processed_dataset(df: pd.DataFrame, output_dir: str):
    path = os.path.join(output_dir, "phishtank_processed.csv")
    df.to_csv(path, index=False)
    print(f"\n[Dataset] Processed dataset saved → {path}")
    print(f"          ({len(df):,} rows — reuse with: python train_model.py --dataset {path})")


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Train phishing detector on PhishTank dataset",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage (downloads legitimate URLs automatically & saves to models/):
  python train_phishtank.py --phishtank data/phishtank_processed.csv

  # Skip re-downloading legit URLs if you already have processed data:
  python train_phishtank.py --phishtank data/phishtank_processed.csv --no-download

  # Custom output folder and more training epochs:
  python train_phishtank.py --phishtank data/phishtank_processed.csv --output ./models --epochs 100
        """
    )
    parser.add_argument("--phishtank",   required=True, help="Path to PhishTank CSV file")
    parser.add_argument("--output",      default="models", help="Output directory for trained model files (default: models)")
    parser.add_argument("--epochs",      type=int, default=60, help="Max training epochs (default: 60)")
    parser.add_argument("--no-download", action="store_true", help="Skip downloading Majestic Million (use built-in fallback)")
    parser.add_argument("--legit-limit", type=int, default=50_000, help="Max legitimate URLs to use (default: 50000)")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    # ── Step 1: Load PhishTank ────────────────────────────────────────────
    if not os.path.exists(args.phishtank):
        print(f"\n❌ ERROR: File not found: {args.phishtank}")
        print("   Download from: https://www.phishtank.com/developer_info.php")
        print("   File name to look for: online-valid.csv")
        return

    phish_df = load_phishtank(args.phishtank)

    # ── Step 2: Get Legitimate URLs ───────────────────────────────────────
    if args.no_download:
        legit_urls = _builtin_legit_urls()
    else:
        legit_urls = download_majestic_million(n=args.legit_limit)

    # ── Step 3: Extract Features ──────────────────────────────────────────
    df = build_feature_dataframe(phish_df, legit_urls)

    # Show class balance
    n_phish = (df["label"] == 1).sum()
    n_legit = (df["label"] == 0).sum()
    print(f"\n[Dataset] Final shape: {df.shape}")
    print(f"          Phishing: {n_phish:,}  |  Legitimate: {n_legit:,}")

    # Save the processed feature CSV for future reruns
    save_processed_dataset(df, args.output)

    # ── Step 4: Prepare Data ──────────────────────────────────────────────
    X = df[FEATURE_COLUMNS].values.astype(np.float32)
    y = df["label"].values.astype(np.float32)

    # Normalise
    scaler   = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    # Train / test split (stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.20, random_state=RANDOM_SEED, stratify=y
    )
    print(f"\n[Split] Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # ── Step 5: Build & Train Model ───────────────────────────────────────
    model = build_model(input_dim=X_train.shape[1])
    model.summary()

    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor="val_auc", patience=8,
            restore_best_weights=True, mode="max", verbose=1,
        ),
        tf.keras.callbacks.ReduceLROnPlateau(
            monitor="val_loss", patience=4, factor=0.5, min_lr=1e-6, verbose=1,
        ),
        tf.keras.callbacks.ModelCheckpoint(
            os.path.join(args.output, "best_model.h5"),
            monitor="val_auc", save_best_only=True, mode="max", verbose=0,
        ),
    ]

    print(f"\n[Training] Starting — up to {args.epochs} epochs...")
    history = model.fit(
        X_train, y_train,
        validation_split=0.15,
        epochs=args.epochs,
        batch_size=64,
        callbacks=callbacks,
        verbose=1,
    )

    plot_training_history(history, args.output)

    # ── Step 6: Evaluate ──────────────────────────────────────────────────
    metrics = evaluate_model(model, X_test, y_test, args.output)

    # ── Step 7: Export TF.js ──────────────────────────────────────────────
    keras_path = os.path.join(args.output, "keras_model.h5")
    model.save(keras_path)
    print(f"\n[Export] ✅ Keras model saved → {keras_path}")

    if TFJS_AVAILABLE:
        print(f"\n[Export] Converting to TensorFlow.js...")
        tfjs.converters.save_keras_model(model, args.output)
        print(f"[Export] ✅ TF.js model saved → {args.output}/")
    else:
        print(f"\n[Export] ⚠  TensorFlow.js conversion skipped (uvloop not supported on Windows).")
        print(f"          To convert the saved Keras model, run in your terminal:")
        print(f"            pip install tensorflowjs --no-deps")
        print(f"            tensorflowjs_converter --input_format keras {keras_path} {args.output}")

    # ── Step 8: Export normalisation params ───────────────────────────────
    export_normalisation_params(scaler, args.output)

    # ── Final summary ─────────────────────────────────────────────────────
    print("\n" + "═" * 55)
    print("  TRAINING COMPLETE — NEXT STEPS")
    print("═" * 55)
    print(f"  1. Copy model files into extension:")
    print(f"     cp {args.output}/model.json ../model/model.json")
    print(f"     cp {args.output}/group1-shard1of1.bin ../model/")
    print(f"  2. Update background.js FEATURE_MINS / FEATURE_MAXS")
    print(f"     (values printed above)")
    print(f"  3. Go to chrome://extensions → click ↺ Reload")
    print(f"  4. Browse any page and click the extension icon")
    print("═" * 55)
    print(f"\n  Final accuracy : {metrics['accuracy']*100:.2f}%")
    print(f"  ROC-AUC        : {metrics['auc']:.4f}")
    print("═" * 55)


if __name__ == "__main__":
    main()