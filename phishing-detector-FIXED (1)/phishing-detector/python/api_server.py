#!/usr/bin/env python3
"""
api_server.py — Phishing Detector REST API Server
====================================================
Serves the advanced XGBoost phishing detection model via Flask.
The extension sends feature vectors and receives phishing scores.

Run: python api_server.py
Then browser extension calls http://localhost:5000/predict

PRIVACY: Server runs locally, no external API calls.
"""

import json
import pickle
import logging
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS

# ─── Setup Logging ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

# ─── Flask App ────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ─── Load Model Files ────────────────────────────────────────────────────────

MODEL_DIR = Path(__file__).parent / "model_advanced"
MODEL_FILE = MODEL_DIR / "phishing_model_advanced.pkl"
SCALER_FILE = MODEL_DIR / "scaler.pkl"
METADATA_FILE = MODEL_DIR / "model_metadata.json"

logger.info(f"Loading model from: {MODEL_FILE}")

try:
    with open(MODEL_FILE, "rb") as f:
        model = pickle.load(f)
    logger.info("✓ Loaded XGBoost model")
except Exception as e:
    logger.error(f"✗ Failed to load model: {e}")
    raise

try:
    with open(SCALER_FILE, "rb") as f:
        scaler = pickle.load(f)
    logger.info("✓ Loaded feature scaler")
except Exception as e:
    logger.error(f"✗ Failed to load scaler: {e}")
    raise

try:
    with open(METADATA_FILE, "r") as f:
        metadata = json.load(f)
    logger.info("✓ Loaded model metadata")
    logger.info(f"  Metadata file contains {len(metadata.get('features', []))} features")
    logger.info(f"  Feature names: {metadata.get('features', [])}")
except Exception as e:
    logger.error(f"✗ Failed to load metadata: {e}")
    raise

# Extract key parameters
OPTIMAL_THRESHOLD = float(metadata.get("optimal_threshold", 0.410))
FEATURE_ORDER = metadata.get("features", [])

logger.info(f"  Model Type: {metadata.get('model_type')}")
logger.info(f"  Accuracy: {metadata.get('accuracy', 0):.2%}")
logger.info(f"  Recall: {metadata.get('recall', 0):.2%}")
logger.info(f"  Optimal Threshold: {OPTIMAL_THRESHOLD:.3f}")
logger.info(f"  Features LOADED: {len(FEATURE_ORDER)} features")
logger.info(f"  FEATURE_ORDER variable set to: {FEATURE_ORDER}")

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "model": metadata.get("model_type"),
        "threshold": OPTIMAL_THRESHOLD,
        "accuracy": metadata.get("accuracy"),
        "recall": metadata.get("recall"),
    })

@app.route("/predict", methods=["POST"])
def predict():
    """
    Predict phishing probability for a URL's features.
    
    Request JSON:
    {
        "features": {
            "url_length": 50,
            "domain_length": 15,
            ...
        }
    }
    
    Response JSON:
    {
        "probability": 0.75,
        "is_phishing": true,
        "confidence": 0.34,  // Distance from threshold
        "threshold": 0.410
    }
    """
    try:
        data = request.get_json()
        
        if not data or "features" not in data:
            return jsonify({"error": "Missing 'features' in request"}), 400
        
        features_dict = data["features"].copy()
        url = data.get("url", "unknown")
        
        # Map feature names: has_http -> is_http, has_https -> is_https
        # (compatibility between JS extraction and model)
        if "has_http" in features_dict or "has_https" in features_dict:
            if "has_http" in features_dict and "is_http" not in features_dict:
                features_dict["is_http"] = features_dict["has_http"]
            if "has_https" in features_dict and "is_https" not in features_dict:
                features_dict["is_https"] = features_dict["has_https"]
        
        # Validate required features
        missing = [f for f in FEATURE_ORDER if f not in features_dict]
        if missing:
            logger.warning(f"Missing features for {url}: {missing}")
            return jsonify({
                "error": f"Missing features: {missing}",
                "url": url
            }), 400
        
        # Build feature vector in correct order
        feature_vector = [[features_dict[f] for f in FEATURE_ORDER]]
        
        # Scale features
        scaled_features = scaler.transform(feature_vector)
        
        # Get prediction probability (probability of phishing class)
        probability = model.predict_proba(scaled_features)[0][1]
        
        # Heuristic boost for obvious phishing indicators
        heuristic_boost = 0
        url_lower = url.lower()
        
        # Suspicious hosting platforms
        suspicious_hosts = [".vercel.app", ".netlify.app", ".github.io", ".glitch.me",
                          ".pages.dev", ".webflow.io", "duckdns.org"]
        for host in suspicious_hosts:
            if host in url_lower:
                heuristic_boost += 0.25
                break
        
        # Typosquatting and clones
        phish_keywords = ["clone", "copy", "login", "verify", "confirm", "update",
                        "backup", "wallet", "crypto", "token", "exchange"]
        keyword_count = sum(1 for kw in phish_keywords if kw in url_lower)
        heuristic_boost += min(keyword_count * 0.1, 0.3)
        
        # Mismatched/suspicious TLDs
        if features_dict.get("suspicious_tld") == 1:
            heuristic_boost += 0.15
        
        # Apply heuristic boost
        boosted_probability = min(probability + heuristic_boost, 0.99)
        
        # Use modified threshold: 0.50 with heuristic boost, original threshold without boost
        # If boost applied, use 0.50; otherwise use original 0.41
        threshold = 0.50 if heuristic_boost > 0.05 else 0.41
        is_phishing = boosted_probability > threshold
        confidence = abs(boosted_probability - threshold)
        
        response = {
            "url": url,
            "probability": float(boosted_probability),
            "model_score": float(probability),
            "is_phishing": bool(is_phishing),
            "confidence": float(confidence),
            "threshold": float(threshold),
            "decision": "PHISHING" if is_phishing else "LEGITIMATE",
        }
        
        # Log predictions
        confidence_level = "HIGH" if confidence > 0.3 else "MEDIUM" if confidence > 0.1 else "LOW"
        log_msg = f"[{response['decision']}] {url} ({probability:.2%}, confidence={confidence_level})"
        logger.info(log_msg)
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/batch_predict", methods=["POST"])
def batch_predict():
    """
    Batch predict multiple URLs at once.
    
    Request JSON:
    {
        "urls": [
            {"url": "http://...", "features": {...}},
            ...
        ]
    }
    
    Response JSON:
    {
        "results": [
            {"url": "...", "probability": 0.75, "is_phishing": true},
            ...
        ]
    }
    """
    try:
        data = request.get_json()
        urls = data.get("urls", [])
        
        if not urls:
            return jsonify({"error": "No URLs provided"}), 400
        
        results = []
        for item in urls:
            url = item.get("url", "unknown")
            features_dict = item.get("features", {}).copy()
            
            # Map feature names: has_http -> is_http, has_https -> is_https
            # (compatibility between JS extraction and model)
            if "has_http" in features_dict or "has_https" in features_dict:
                if "has_http" in features_dict and "is_http" not in features_dict:
                    features_dict["is_http"] = features_dict["has_http"]
                if "has_https" in features_dict and "is_https" not in features_dict:
                    features_dict["is_https"] = features_dict["has_https"]
            
            # Skip if missing features
            missing = [f for f in FEATURE_ORDER if f not in features_dict]
            if missing:
                results.append({
                    "url": url,
                    "error": f"Missing features: {missing}"
                })
                continue
            
            # Build and score
            feature_vector = [[features_dict[f] for f in FEATURE_ORDER]]
            scaled_features = scaler.transform(feature_vector)
            probability = model.predict_proba(scaled_features)[0][1]
            
            # Heuristic boost for obvious phishing indicators
            heuristic_boost = 0
            url_lower = url.lower()
            
            # Suspicious hosting platforms commonly used for phishing
            suspicious_hosts = [".vercel.app", ".netlify.app", ".github.io", ".glitch.me",
                              ".pages.dev", ".webflow.io", "duckdns.org"]
            for host in suspicious_hosts:
                if host in url_lower:
                    heuristic_boost += 0.25
                    break
            
            # Typosquatting and clones
            phish_keywords = ["clone", "copy", "login", "verify", "confirm", "update",
                            "backup", "wallet", "crypto", "token", "exchange"]
            keyword_count = sum(1 for kw in phish_keywords if kw in url_lower)
            heuristic_boost += min(keyword_count * 0.1, 0.3)
            
            # Mismatched/suspicious TLDs
            if features_dict.get("suspicious_tld") == 1:
                heuristic_boost += 0.15
            
            # Apply heuristic boost (up to maximum of 0.15 cap on probability)
            boosted_probability = min(probability + heuristic_boost, 0.99)
            
            # Use modified threshold: 0.50 with heuristic boost, original threshold without boost
            # If boost applied, use 0.50; otherwise use original 0.41
            threshold = 0.50 if heuristic_boost > 0.05 else 0.41
            is_phishing = boosted_probability > threshold
            
            results.append({
                "url": url,
                "probability": float(boosted_probability),
                "model_score": float(probability),
                "is_phishing": bool(is_phishing),
                "threshold": float(threshold),
                "decision": "PHISHING" if is_phishing else "LEGITIMATE",
            })
        
        logger.info(f"Batch prediction: {len(results)} URLs processed")
        
        return jsonify({
            "count": len(results),
            "results": results
        })
    
    except Exception as e:
        logger.error(f"Batch prediction error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/metadata", methods=["GET"])
def get_metadata():
    """Get model metadata."""
    return jsonify({
        "model_type": metadata.get("model_type"),
        "features": len(FEATURE_ORDER),
        "feature_names": FEATURE_ORDER,
        "accuracy": metadata.get("accuracy"),
        "precision": metadata.get("precision"),
        "recall": metadata.get("recall"),
        "f1": metadata.get("f1"),
        "auc": metadata.get("auc"),
        "optimal_threshold": OPTIMAL_THRESHOLD,
        "whitelist_enabled": metadata.get("whitelist_enabled", True)
    })

# ─── Main ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("🚀 Phishing Detector API Server")
    logger.info("=" * 60)
    logger.info(f"Model: XGBoost (Advanced)")
    logger.info(f"Accuracy: {metadata.get('accuracy', 0):.2%}")
    logger.info(f"Recall: {metadata.get('recall', 0):.2%} (catches phishing)")
    logger.info(f"Decision Threshold: {OPTIMAL_THRESHOLD:.3f}")
    logger.info("")
    logger.info("📍 Starting server on http://localhost:5000")
    logger.info("")
    logger.info("Endpoints:")
    logger.info("  POST /predict - Predict single URL")
    logger.info("  POST /batch_predict - Predict multiple URLs")
    logger.info("  GET /health - Health check")
    logger.info("  GET /metadata - Model information")
    logger.info("=" * 60)
    
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
