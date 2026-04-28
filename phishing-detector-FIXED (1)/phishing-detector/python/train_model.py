#!/usr/bin/env python3
"""
train_model.py — Phishing Detection Master
==========================================
Trains a Neural Network on phishing URL feature data,
evaluates it, and exports it to TensorFlow.js format.

Requirements:
    pip install tensorflow pandas scikit-learn tensorflowjs matplotlib seaborn

Dataset format (CSV):
    url_length, dot_count, has_at, is_https, subdomain_count,
    is_ip_address, suspicious_tld, form_action_mismatch,
    has_password_field, external_script_count, label
    (label: 1 = phishing, 0 = legitimate)

Usage:
    python train_model.py --dataset phishing_data.csv --output ./tfjs_model

Author: Capstone Cybersecurity Project
"""

import argparse
import os
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import tensorflow as tf

from sklearn.model_selection   import train_test_split, StratifiedKFold
from sklearn.preprocessing     import MinMaxScaler
from sklearn.metrics           import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, classification_report,
)
import tensorflowjs as tfjs

# ─── Configuration ─────────────────────────────────────────────────────────────

FEATURE_COLUMNS = [
    "url_length",
    "dot_count",
    "has_at",
    "is_https",
    "subdomain_count",
    "is_ip_address",
    "suspicious_tld",
    "form_action_mismatch",
    "has_password_field",
    "external_script_count",
]

LABEL_COLUMN  = "label"
RANDOM_SEED   = 42
TEST_SIZE     = 0.20
BATCH_SIZE    = 64
EPOCHS        = 50
EARLY_STOP_PATIENCE = 8

np.random.seed(RANDOM_SEED)
tf.random.set_seed(RANDOM_SEED)


# ─── Dataset Generation (Demo) ─────────────────────────────────────────────────

def generate_synthetic_dataset(n_samples: int = 10_000) -> pd.DataFrame:
    """
    Generate a synthetic phishing dataset for demonstration purposes.
    In production, replace this with real labelled data (PhishTank, OpenPhish,
    ISCX-URL-2016, UCDAVIS-URL dataset, etc.).

    Phishing URL characteristics modelled here are based on published
    academic feature engineering papers (Sahoo et al., 2017; Buber et al., 2017).
    """
    rng = np.random.default_rng(RANDOM_SEED)
    n_phish = n_samples // 2

    # ── Phishing samples ───────────────────────────────────────────────────
    phish = pd.DataFrame({
        "url_length":            rng.integers(80, 512,  n_phish),
        "dot_count":             rng.integers(3,  8,    n_phish),
        "has_at":                rng.choice([0, 1], n_phish, p=[0.3, 0.7]),
        "is_https":              rng.choice([0, 1], n_phish, p=[0.6, 0.4]),
        "subdomain_count":       rng.integers(2,  5,    n_phish),
        "is_ip_address":         rng.choice([0, 1], n_phish, p=[0.5, 0.5]),
        "suspicious_tld":        rng.choice([0, 1], n_phish, p=[0.2, 0.8]),
        "form_action_mismatch":  rng.choice([0, 1], n_phish, p=[0.3, 0.7]),
        "has_password_field":    rng.choice([0, 1], n_phish, p=[0.2, 0.8]),
        "external_script_count": rng.integers(5,  30,   n_phish),
        "label": 1,
    })

    # ── Legitimate samples ─────────────────────────────────────────────────
    legit = pd.DataFrame({
        "url_length":            rng.integers(10, 120,  n_phish),
        "dot_count":             rng.integers(1,  3,    n_phish),
        "has_at":                rng.choice([0, 1], n_phish, p=[0.95, 0.05]),
        "is_https":              rng.choice([0, 1], n_phish, p=[0.1, 0.9]),
        "subdomain_count":       rng.integers(0,  2,    n_phish),
        "is_ip_address":         rng.choice([0, 1], n_phish, p=[0.98, 0.02]),
        "suspicious_tld":        rng.choice([0, 1], n_phish, p=[0.95, 0.05]),
        "form_action_mismatch":  rng.choice([0, 1], n_phish, p=[0.9, 0.1]),
        "has_password_field":    rng.choice([0, 1], n_phish, p=[0.6, 0.4]),
        "external_script_count": rng.integers(0,  8,    n_phish),
        "label": 0,
    })

    df = pd.concat([phish, legit]).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    print(f"[Dataset] Generated {len(df):,} samples ({n_phish:,} phishing / {n_phish:,} legitimate)")
    return df


# ─── Model Architecture ────────────────────────────────────────────────────────

def build_model(input_dim: int) -> tf.keras.Model:
    """
    Dense neural network for binary phishing classification.
    Architecture chosen for low latency inference inside TensorFlow.js:
        Input(10) → Dense(16, relu) → Dropout(0.3)
                  → Dense(8,  relu) → Dropout(0.2)
                  → Dense(1,  sigmoid)

    Total parameters: ~250 — fast enough for real-time browser inference.
    """
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(input_dim,), name="features"),

        tf.keras.layers.Dense(16, activation="relu", name="hidden1",
                              kernel_regularizer=tf.keras.regularizers.l2(1e-4)),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.3),

        tf.keras.layers.Dense(8, activation="relu", name="hidden2",
                              kernel_regularizer=tf.keras.regularizers.l2(1e-4)),
        tf.keras.layers.Dropout(0.2),

        tf.keras.layers.Dense(1, activation="sigmoid", name="output"),
    ], name="PhishingDetector")

    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=["accuracy", tf.keras.metrics.AUC(name="auc"),
                 tf.keras.metrics.Precision(name="precision"),
                 tf.keras.metrics.Recall(name="recall")],
    )
    return model


# ─── Evaluation ────────────────────────────────────────────────────────────────

def evaluate_model(model, X_test, y_test, threshold=0.5):
    """
    Compute and print accuracy, precision, recall, F1, ROC-AUC,
    and render a confusion matrix heatmap.
    """
    y_prob = model.predict(X_test, verbose=0).ravel()
    y_pred = (y_prob >= threshold).astype(int)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec  = recall_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred)
    auc  = roc_auc_score(y_test, y_prob)

    print("\n" + "=" * 50)
    print("  MODEL EVALUATION RESULTS")
    print("=" * 50)
    print(f"  Accuracy  : {acc:.4f}  ({acc*100:.2f}%)")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1 Score  : {f1:.4f}")
    print(f"  ROC-AUC   : {auc:.4f}")
    print("=" * 50)
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Reds",
                xticklabels=["Legitimate", "Phishing"],
                yticklabels=["Legitimate", "Phishing"])
    plt.title("Confusion Matrix — Phishing Detector")
    plt.ylabel("True Label"); plt.xlabel("Predicted Label")
    plt.tight_layout()
    plt.savefig("confusion_matrix.png", dpi=150)
    print("\n  Confusion matrix saved to confusion_matrix.png")

    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "auc": auc}


def plot_training_history(history):
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    axes[0].plot(history.history["accuracy"],     label="Train Accuracy")
    axes[0].plot(history.history["val_accuracy"], label="Val Accuracy")
    axes[0].set_title("Accuracy"); axes[0].legend()

    axes[1].plot(history.history["loss"],     label="Train Loss")
    axes[1].plot(history.history["val_loss"], label="Val Loss")
    axes[1].set_title("Loss"); axes[1].legend()

    plt.tight_layout()
    plt.savefig("training_history.png", dpi=150)
    print("  Training history plot saved to training_history.png")


# ─── Feature Norm Export ──────────────────────────────────────────────────────

def export_normalisation_params(scaler: MinMaxScaler, output_dir: str):
    """
    Export the min/max values used for normalisation.
    These are hardcoded into background.js — keep them in sync.
    """
    params = {
        "feature_mins": scaler.data_min_.tolist(),
        "feature_maxs": scaler.data_max_.tolist(),
        "feature_names": FEATURE_COLUMNS,
    }
    path = os.path.join(output_dir, "normalisation_params.json")
    with open(path, "w") as f:
        json.dump(params, f, indent=2)
    print(f"\n  Normalisation params exported to {path}")
    print("  ⚠  Copy FEATURE_MINS and FEATURE_MAXS arrays into background.js!")
    print(f"     FEATURE_MINS = {params['feature_mins']}")
    print(f"     FEATURE_MAXS = {params['feature_maxs']}")


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Train Phishing Detection Neural Network")
    parser.add_argument("--dataset", type=str, default=None,
                        help="Path to labelled CSV dataset. If omitted, synthetic data is generated.")
    parser.add_argument("--output",  type=str, default="./tfjs_model",
                        help="Directory to export the TensorFlow.js model.")
    parser.add_argument("--epochs",  type=int, default=EPOCHS)
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    # ── Load / generate dataset ───────────────────────────────────────────
    if args.dataset and os.path.exists(args.dataset):
        df = pd.read_csv(args.dataset)
        print(f"[Dataset] Loaded {len(df):,} samples from {args.dataset}")
    else:
        print("[Dataset] No dataset provided. Generating synthetic data...")
        df = generate_synthetic_dataset(n_samples=20_000)
        df.to_csv("synthetic_phishing_data.csv", index=False)
        print("[Dataset] Saved to synthetic_phishing_data.csv")

    # Validate
    assert LABEL_COLUMN in df.columns, f"Missing label column '{LABEL_COLUMN}'"
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            raise ValueError(f"Missing feature column: '{col}'")

    X = df[FEATURE_COLUMNS].values.astype(np.float32)
    y = df[LABEL_COLUMN].values.astype(np.float32)

    print(f"\n[Features] Shape: {X.shape}  |  Class balance: "
          f"{(y==0).sum()} legitimate / {(y==1).sum()} phishing")

    # ── Normalise ─────────────────────────────────────────────────────────
    scaler  = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    # ── Train / test split ────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )
    print(f"\n[Split] Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # ── Build model ───────────────────────────────────────────────────────
    model = build_model(input_dim=X_train.shape[1])
    model.summary()

    # ── Train ─────────────────────────────────────────────────────────────
    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor="val_auc", patience=EARLY_STOP_PATIENCE,
            restore_best_weights=True, mode="max"
        ),
        tf.keras.callbacks.ReduceLROnPlateau(
            monitor="val_loss", patience=4, factor=0.5, min_lr=1e-6
        ),
    ]

    print(f"\n[Training] Starting for up to {args.epochs} epochs...")
    history = model.fit(
        X_train, y_train,
        validation_split=0.15,
        epochs=args.epochs,
        batch_size=BATCH_SIZE,
        callbacks=callbacks,
        verbose=1,
    )

    plot_training_history(history)

    # ── Evaluate ──────────────────────────────────────────────────────────
    metrics = evaluate_model(model, X_test, y_test)

    # ── Export Keras model ────────────────────────────────────────────────
    keras_path = os.path.join(args.output, "keras_model.h5")
    model.save(keras_path)
    print(f"\n[Export] Keras model saved to {keras_path}")

    # ── Export to TensorFlow.js ───────────────────────────────────────────
    print(f"\n[Export] Converting to TensorFlow.js format...")
    tfjs.converters.save_keras_model(model, args.output)
    print(f"[Export] TF.js model saved to {args.output}/")
    print(f"         Copy the contents of {args.output}/ into your extension's /model/ folder.")

    # ── Export normalisation params ───────────────────────────────────────
    export_normalisation_params(scaler, args.output)

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 50)
    print("  EXPORT COMPLETE")
    print("=" * 50)
    print(f"  Model accuracy : {metrics['accuracy']*100:.2f}%")
    print(f"  ROC-AUC        : {metrics['auc']:.4f}")
    print(f"\n  Next steps:")
    print(f"    1. Copy {args.output}/ → extension/model/")
    print(f"    2. Update FEATURE_MINS / FEATURE_MAXS in background.js")
    print(f"    3. Reload the extension in chrome://extensions")
    print("=" * 50)


if __name__ == "__main__":
    main()
