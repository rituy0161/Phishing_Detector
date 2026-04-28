#!/usr/bin/env python3
"""
train_simple.py — Simplified training script without tensorflowjs dependency
This version trains the model and saves it in Keras format,
which works with the existing model converter scripts.
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
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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

# ─── Legitimate URLs ───────────────────────────────────────────────────────────

def get_builtin_legit_urls() -> list:
    """Get built-in list of legitimate domains."""
    domains = [
        "google.com", "youtube.com", "facebook.com", "twitter.com",
        "instagram.com", "linkedin.com", "amazon.com", "wikipedia.org",
        "reddit.com", "netflix.com", "github.com", "stackoverflow.com",
        "microsoft.com", "apple.com", "adobe.com", "dropbox.com",
        "spotify.com", "paypal.com", "ebay.com", "yahoo.com",
        "bing.com", "twitch.tv", "discord.com", "slack.com",
        "zoom.us", "shopify.com", "wordpress.com", "medium.com",
    ]
    urls = []
    for d in domains:
        for sub in ["www", "mail", "login"]:
            urls.append(f"https://{sub}.{d}")
    return urls * 100

# ─── Dataset Loading ──────────────────────────────────────────────────────────

def load_phishtank(csv_path: str) -> pd.DataFrame:
    """Load PhishTank CSV file."""
    print(f"\n[Dataset] Loading: {csv_path}")
    df = pd.read_csv(csv_path, encoding="utf-8", on_bad_lines="skip")
    
    # Normalize column names
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    
    # Find URL column
    url_col = None
    for col in ["url", "phish_detail_url"]:
        if col in df.columns:
            url_col = col
            break
    
    if not url_col:
        url_col = df.columns[0]
    
    print(f"[Dataset] Using URL column: {url_col}")
    urls = df[url_col].dropna().astype(str).head(10000).tolist()  # Limit to 10k for speed
    
    print(f"[Dataset] Loaded {len(urls):,} phishing URLs")
    return pd.DataFrame({"url": urls, "label": 1})

# ─── Feature Extraction ────────────────────────────────────────────────────────

def build_feature_dataframe(phish_df: pd.DataFrame, legit_urls: list) -> pd.DataFrame:
    """Extract features from all URLs."""
    legit_df = pd.DataFrame({"url": legit_urls, "label": 0})
    
    # Balance
    n = min(len(phish_df), len(legit_df))
    phish_df = phish_df.sample(n, random_state=RANDOM_SEED)
    legit_df = legit_df.sample(n, random_state=RANDOM_SEED)
    
    combined = pd.concat([phish_df, legit_df]).sample(frac=1, random_state=RANDOM_SEED)
    
    print(f"\n[Features] Extracting from {len(combined):,} URLs...")
    
    feature_rows = []
    for i, row in combined.iterrows():
        feats = extract_features(row["url"])
        feats["label"] = int(row["label"])
        feature_rows.append(feats)
        
        if (i + 1) % 2000 == 0:
            print(f"  Progress: {i+1:,} URLs processed", end="\r")
    
    print(f"\n[Features] Extraction complete")
    return pd.DataFrame(feature_rows)

# ─── Model ────────────────────────────────────────────────────────────────────

def build_model(input_dim: int) -> tf.keras.Model:
    """Build neural network model."""
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(input_dim,)),
        tf.keras.layers.Dense(32, activation="relu"),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.Dense(16, activation="relu"),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(8, activation="relu"),
        tf.keras.layers.Dense(1, activation="sigmoid"),
    ], name="PhishingDetector")
    
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=["accuracy", tf.keras.metrics.AUC(name="auc")],
    )
    return model

# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Train phishing detector model")
    parser.add_argument("--phishtank", required=True, help="Path to PhishTank CSV file")
    parser.add_argument("--output", default="./model", help="Output directory for model")
    parser.add_argument("--epochs", type=int, default=20, help="Training epochs")
    args = parser.parse_args()
    
    os.makedirs(args.output, exist_ok=True)
    
    # Load and prepare data
    phish_df = load_phishtank(args.phishtank)
    legit_urls = get_builtin_legit_urls()
    
    df = build_feature_dataframe(phish_df, legit_urls)
    
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
                monitor="val_auc", patience=5, restore_best_weights=True, mode="max"
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
    
    print("\n" + "═" * 55)
    print("  TRAINING RESULTS")
    print("═" * 55)
    print(f"  Accuracy   : {acc  * 100:.2f}%")
    print(f"  Precision  : {prec * 100:.2f}%")
    print(f"  Recall     : {rec  * 100:.2f}%")
    print(f"  F1 Score   : {f1   * 100:.2f}%")
    print(f"  ROC-AUC    : {auc_:.4f}")
    print("═" * 55)
    
    # Save model
    model_path = os.path.join(args.output, "phishing_model.h5")
    model.save(model_path)
    print(f"\n[Save] Model saved → {model_path}")
    
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
    
    print("\n" + "═" * 55)
    print("  UPDATE background.js WITH THESE VALUES:")
    print("═" * 55)
    print(f"  const FEATURE_MINS = {params['feature_mins']};")
    print(f"  const FEATURE_MAXS = {params['feature_maxs']};")
    print("═" * 55)
    print("\n✅ Training complete! Model ready for deployment.")

if __name__ == "__main__":
    main()
