#!/usr/bin/env python3
"""
convert_model.py — Convert Keras .h5 model to TensorFlow.js format
===================================================================
Bypasses tensorflowjs CLI dependency conflicts on Windows + TF 2.20.

Usage:
    python convert_model.py
"""

import os
import json
import struct
import numpy as np

def convert_keras_to_tfjs(h5_path: str, output_dir: str):
    """
    Manually convert a Keras .h5 model to TF.js LayersModel format.
    Produces model.json + group1-shard1of1.bin
    """
    import tensorflow as tf

    print(f"[Convert] Loading Keras model from: {h5_path}")
    model = tf.keras.models.load_model(h5_path)
    model.summary()

    os.makedirs(output_dir, exist_ok=True)

    # ── Step 1: Extract all weights into one flat binary blob ──────────────
    all_weights = []
    weight_manifest = []

    byte_offset = 0

    for layer in model.layers:
        weights = layer.get_weights()
        if not weights:
            continue

        layer_weights = []
        for i, w in enumerate(weights):
            w = w.astype(np.float32)
            weight_name = f"{layer.name}/{layer.weights[i].name.split('/')[-1]}"
            num_bytes   = w.nbytes

            layer_weights.append({
                "name":   weight_name,
                "shape":  list(w.shape),
                "dtype":  "float32",
                "data":   w,
            })

            all_weights.append(w)
            byte_offset += num_bytes

        weight_manifest.append({
            "paths":   ["group1-shard1of1.bin"],
            "weights": [
                {
                    "name":  ww["name"],
                    "shape": ww["shape"],
                    "dtype": ww["dtype"],
                }
                for ww in layer_weights
            ],
        })

    # ── Step 2: Write binary weights file ─────────────────────────────────
    bin_path = os.path.join(output_dir, "group1-shard1of1.bin")
    with open(bin_path, "wb") as f:
        for w in all_weights:
            f.write(w.tobytes())

    print(f"[Convert] Weights written → {bin_path}  ({os.path.getsize(bin_path):,} bytes)")

    # ── Step 3: Build model.json ───────────────────────────────────────────
    model_config = json.loads(model.to_json())

    model_json = {
        "format":          "layers-model",
        "generatedBy":     f"TensorFlow.js tfjs-layers v4.20.0",
        "convertedBy":     "convert_model.py (manual converter)",
        "modelTopology":   model_config,
        "weightsManifest": weight_manifest,
        "trainingConfig":  None,
    }

    json_path = os.path.join(output_dir, "model.json")
    with open(json_path, "w") as f:
        json.dump(model_json, f)

    print(f"[Convert] model.json written → {json_path}")

    # ── Step 4: Verify ────────────────────────────────────────────────────
    print(f"\n[Verify] Files in {output_dir}:")
    for fname in os.listdir(output_dir):
        fpath = os.path.join(output_dir, fname)
        print(f"         {fname}  ({os.path.getsize(fpath):,} bytes)")

    print("\n[Convert] ✅ Done! Copy model.json and group1-shard1of1.bin into your extension's models/ folder.")


if __name__ == "__main__":
    H5_PATH    = "models/keras_model.h5"
    OUTPUT_DIR = "models"

    if not os.path.exists(H5_PATH):
        print(f"[Error] File not found: {H5_PATH}")
        print(f"        Current directory: {os.getcwd()}")
        print("        Make sure you run this from your extension root folder (where manifest.json is).")
        print("        e.g.:  cd phishing-detector  →  python convert_model.py")
        exit(1)

    convert_keras_to_tfjs(H5_PATH, OUTPUT_DIR)
