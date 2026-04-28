#!/usr/bin/env python3
"""
train_phishtank_full.py — Train using actual PhishTank datasets
================================================================
Uses:
  - verified_online.csv (phishing URLs)
  - urls.csv or phishtank_processed.csv (legitimate URLs)

Usage:
  python train_phishtank_full.py --phishing ../data/verified_online.csv --legit ../data/urls.csv --epochs 30
"""

import os
import sys
import json
import argparse
import numpy as np
import pandas as pd
import tensorflow as tf
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# ─── Constants ─────────────────────────────────────────────────────────────────

RANDOM_SEED = 42
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work",
    "date", "racing", "review", "win", "bid", "stream", "gdn", "link",
}

FEATURE_COLUMNS = [
    "url_length", "dot_count", "has_at", "is_https", "subdomain_count",
    "is_ip_address", "suspicious_tld", "form_action_mismatch",
    "has_password_field", "external_script_count",
]

# ─── Helper Functions ──────────────────────────────────────────────────────────

def is_ip_address(hostname: str) -> bool:
    """Check if hostname is an IP address."""
    try:
        parts = hostname.split(".")
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)
    except:
        return False

def count_subdomains(hostname: str) -> int:
    """Count subdomains in hostname."""
    if not hostname:
        return 0
    parts = hostname.split(".")
    return max(0, len(parts) - 2)

def has_suspicious_tld(hostname: str) -> bool:
    """Check if TLD is suspicious."""
    try:
        parts = hostname.split(".")
        if len(parts) < 2:
            return False
        tld = parts[-1].lower()
        return tld in SUSPICIOUS_TLDS
    except:
        return False

def extract_features(raw_url: str) -> dict:
    """Extract features from a single URL."""
    features = {
        "url_length":            0,
        "dot_count":             0,
        "has_at":                0,
        "is_https":              0,
        "subdomain_count":       0,
        "is_ip_address":         0,
        "suspicious_tld":        0,
        "form_action_mismatch":  0,
        "has_password_field":    0,
        "external_script_count": 0,
    }

    try:
        raw_url = raw_url.strip()
        if not raw_url or raw_url.startswith("#"):
            return features
            
        features["url_length"] = len(raw_url)
        features["has_at"] = 1 if "@" in raw_url else 0

        parsed = urlparse(raw_url)
        hostname = parsed.hostname or ""

        if hostname:
            features["is_https"] = 1 if parsed.scheme == "https" else 0
            features["dot_count"] = hostname.count(".")
            features["subdomain_count"] = count_subdomains(hostname)
            features["is_ip_address"] = 1 if is_ip_address(hostname) else 0
            features["suspicious_tld"] = 1 if has_suspicious_tld(hostname) else 0
    except:
        pass

    return features

# ─── Dataset Loading ──────────────────────────────────────────────────────────

def load_urls_csv(csv_path: str, label: int, limit: int = None) -> pd.DataFrame:
    """Load URLs from CSV file (phishing or legitimate)."""
    print(f"\n[Dataset] Loading from: {csv_path}")
    
    try:
        # Try different encodings
        try:
            df = pd.read_csv(csv_path, encoding="utf-8", on_bad_lines="skip")
        except:
            df = pd.read_csv(csv_path, encoding="latin-1", on_bad_lines="skip")
    except Exception as e:
        print(f"[Error] Could not load {csv_path}: {e}")
        return pd.DataFrame()
    
    # Normalize column names
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    
    print(f"[Dataset] Columns found: {list(df.columns)}")
    
    # Find URL column
    url_col = None
    for col in ["url", "phish_detail_url", "domain", "link"]:
        if col in df.columns:
            url_col = col
            break
    
    if not url_col:
        # Use first column
        url_col = df.columns[0]
    
    print(f"[Dataset] Using URL column: '{url_col}'")
    
    urls = df[url_col].dropna().astype(str).unique().tolist()
    
    # Filter out empty and invalid URLs
    urls = [u.strip() for u in urls if u.strip() and not u.startswith("#")]
    
    if limit:
        urls = urls[:limit]
    
    label_name = "phishing" if label == 1 else "legitimate"
    print(f"[Dataset] Loaded {len(urls):,} {label_name} URLs")
    
    return pd.DataFrame({"url": urls, "label": label})

# ─── Feature Extraction ────────────────────────────────────────────────────────

def build_feature_dataframe(dfs: list) -> pd.DataFrame:
    """Extract features from all URLs."""
    combined = pd.concat(dfs).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    total = len(combined)
    
    print(f"\n[Features] Extracting from {total:,} total URLs...")
    print(f"           (Phishing: {(combined['label']==1).sum():,}  Legitimate: {(combined['label']==0).sum():,})")
    
    feature_rows = []
    for i, row in combined.iterrows():
        feats = extract_features(row["url"])
        feats["label"] = int(row["label"])
        feature_rows.append(feats)
        
        if (i + 1) % 5000 == 0 or (i + 1) == total:
            print(f"  Progress: {i+1:,}/{total:,} URLs", end="\r")
    
    print(f"\n[Features] Extraction complete")
    return pd.DataFrame(feature_rows)

# ─── Model ────────────────────────────────────────────────────────────────────

def build_model(input_dim: int) -> tf.keras.Model:
    """Build neural network model."""
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(input_dim,)),
        tf.keras.layers.Dense(64, activation="relu", kernel_regularizer=tf.keras.regularizers.l2(1e-4)),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.4),
        tf.keras.layers.Dense(32, activation="relu", kernel_regularizer=tf.keras.regularizers.l2(1e-4)),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.Dense(16, activation="relu"),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(1, activation="sigmoid"),
    ], name="PhishingDetector")
    
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=["accuracy", tf.keras.metrics.AUC(name="auc"), tf.keras.metrics.Precision(), tf.keras.metrics.Recall()],
    )
    return model

# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Train phishing detector using PhishTank datasets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train with verified phishing and legitimate URLs:
  python train_phishtank_full.py --phishing ../data/verified_online.csv --legit ../data/urls.csv --epochs 30

  # Use processed phishing data:
  python train_phishtank_full.py --phishing ../data/phishtank_processed.csv --legit ../data/urls.csv --epochs 25
        """
    )
    parser.add_argument("--phishing",  required=True, help="Path to phishing URLs CSV")
    parser.add_argument("--legit",     required=True, help="Path to legitimate URLs CSV")
    parser.add_argument("--output",    default="./model", help="Output directory for model")
    parser.add_argument("--epochs",    type=int, default=30, help="Training epochs")
    parser.add_argument("--phish-limit", type=int, default=None, help="Max phishing URLs to load")
    parser.add_argument("--legit-limit", type=int, default=None, help="Max legitimate URLs to load")
    args = parser.parse_args()
    
    os.makedirs(args.output, exist_ok=True)
    
    # Load datasets
    phish_df = load_urls_csv(args.phishing, label=1, limit=args.phish_limit)
    legit_df = load_urls_csv(args.legit, label=0, limit=args.legit_limit)
    
    if phish_df.empty or legit_df.empty:
        print("\n❌ Error: Could not load datasets")
        return
    
    # Balance classes
    n = min(len(phish_df), len(legit_df))
    phish_df = phish_df.sample(n, random_state=RANDOM_SEED)
    legit_df = legit_df.sample(n, random_state=RANDOM_SEED)
    
    # Extract features
    df = build_feature_dataframe([phish_df, legit_df])
    
    print(f"\n[Data] Balanced dataset shape: {df.shape}")
    print(f"       Phishing: {(df['label']==1).sum():,}  Legitimate: {(df['label']==0).sum():,}")
    
    # Prepare and normalize
    X = df[FEATURE_COLUMNS].values.astype(np.float32)
    y = df["label"].values.astype(np.float32)
    
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.20, random_state=RANDOM_SEED, stratify=y
    )
    
    print(f"\n[Split] Train: {len(X_train):,}  Test: {len(X_test):,}")
    
    # Train model
    model = build_model(input_dim=X_train.shape[1])
    
    print(f"\n[Training] Starting {args.epochs} epochs...")
    history = model.fit(
        X_train, y_train,
        validation_split=0.15,
        epochs=args.epochs,
        batch_size=64,
        callbacks=[
            tf.keras.callbacks.EarlyStopping(
                monitor="val_auc", patience=8, restore_best_weights=True, mode="max", verbose=1
            ),
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor="val_loss", patience=4, factor=0.5, min_lr=1e-6, verbose=0
            ),
        ],
        verbose=1,
    )
    
    # Evaluate
    print(f"\n[Evaluation] Testing on {len(X_test):,} URLs...")
    y_prob = model.predict(X_test, verbose=0).ravel()
    y_pred = (y_prob >= 0.5).astype(int)
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc_ = roc_auc_score(y_test, y_prob)
    
    print("\n" + "═" * 60)
    print("  PHISHTANK MODEL EVALUATION RESULTS")
    print("═" * 60)
    print(f"  Accuracy   : {acc  * 100:.2f}%")
    print(f"  Precision  : {prec * 100:.2f}%")
    print(f"  Recall     : {rec  * 100:.2f}%")
    print(f"  F1 Score   : {f1   * 100:.2f}%")
    print(f"  ROC-AUC    : {auc_:.4f}")
    print("═" * 60)
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    
    # Save evaluation plots
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt="d", cmap="Reds",
                xticklabels=["Legitimate", "Phishing"],
                yticklabels=["Legitimate", "Phishing"],
                ax=axes[0])
    axes[0].set_title("Confusion Matrix")
    axes[0].set_ylabel("True Label")
    axes[0].set_xlabel("Predicted Label")
    
    axes[1].plot(history.history["val_auc"], label="Validation AUC", color="crimson", linewidth=2)
    axes[1].plot(history.history["auc"], label="Training AUC", color="steelblue", linewidth=2)
    axes[1].set_title("Model AUC per Epoch")
    axes[1].set_xlabel("Epoch")
    axes[1].set_ylabel("AUC")
    axes[1].legend()
    axes[1].grid(alpha=0.3)
    
    plt.tight_layout()
    plots_path = os.path.join(args.output, "evaluation_plots.png")
    plt.savefig(plots_path, dpi=150)
    print(f"\n[Save] Evaluation plots → {plots_path}")
    
    # Save model
    model_path = os.path.join(args.output, "phishing_model.h5")
    model.save(model_path)
    print(f"[Save] Model saved → {model_path}")
    
    # Save normalization params
    params = {
        "feature_names": FEATURE_COLUMNS,
        "feature_mins": scaler.data_min_.tolist(),
        "feature_maxs": scaler.data_max_.tolist(),
    }
    
    params_path = os.path.join(args.output, "normalisation_params.json")
    with open(params_path, "w") as f:
        json.dump(params, f, indent=2)
    
    print(f"[Save] Normalization params → {params_path}")
    
    print("\n" + "═" * 60)
    print("  UPDATE background.js WITH THESE VALUES:")
    print("═" * 60)
    print(f"  const FEATURE_MINS = {params['feature_mins']};")
    print(f"  const FEATURE_MAXS = {params['feature_maxs']};")
    print("═" * 60)
    print("\n✅ Training complete! Model ready for deployment.")

if __name__ == "__main__":
    main()
