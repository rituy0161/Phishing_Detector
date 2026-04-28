#!/usr/bin/env python3
"""
test_real_websites.py — Test Phishing Detector on Real Websites
================================================================
Tests the Flask API backend against real URLs.

Includes:
- Legitimate website URLs (Google, Amazon, etc.)
- Known phishing indicators (suspicious TLDs, patterns)
- Performance metrics
"""

import json
import time
import requests
from pathlib import Path
from collections import defaultdict

# ─── Configuration ────────────────────────────────────────────────────────────

API_URL = "http://localhost:5000/predict"
HEALTH_URL = "http://localhost:5000/health"

# Real legitimate websites (should score LOW)
LEGITIMATE_URLS = [
    "https://www.google.com",
    "https://www.amazon.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.facebook.com",
    "https://www.linkedin.com",
    "https://www.github.com",
    "https://www.wikipedia.org",
    "https://stackoverflow.com",
    "https://www.youtube.com",
    "https://www.reddit.com",
    "https://www.netflix.com",
    "https://www.paypal.com",
    "https://www.ebay.com",
    "https://mail.google.com",
    "https://www.twitter.com",
    "https://www.instagram.com",
    "https://www.slack.com",
    "https://www.zoom.us",
    "https://www.twitch.tv",
]

# Known phishing patterns (should score HIGH)
PHISHING_URLS = [
    "http://g00gle.com/login",
    "http://amaz0n.com/account-confirm",
    "http://paypa1.com/verify-identity",
    "http://secure-appl3.tk/update-payment",
    "http://verify-account.ml/login",
    "http://192.168.1.1/update",  # IP address
    "https://accounts.google.com@suspicious.tk/login",  # @ symbol (phishing)
    "https://microsoft-security.xyz/verify",  # Suspicious TLD
    "https://bank-confirm.download/action",  # Suspicious TLD
    "http://confirm-account.press/update",  # Suspicious word + TLD
    "http://update-password123456789.top/verify",  # Suspicious pattern
    "http://a.b.c.d.e.f.example.com/login",  # Many subdomains
]

# Edge cases (uncertain)
EDGE_CASES = [
    "https://internal.company.local/admin",  # Internal website
    "https://localhost:8000/test",  # Localhost
    "https://192.168.1.254/router-admin",  # Router IP
]

# ─── Helper Functions ────────────────────────────────────────────────────────

def check_api_health():
    """Check if API server is running."""
    try:
        response = requests.get(HEALTH_URL, timeout=2)
        if response.status_code == 200:
            data = response.json()
            print(f"✓ API Server is running")
            print(f"  Model: {data.get('model')}")
            print(f"  Accuracy: {data.get('accuracy', 0):.2%}")
            print(f"  Recall: {data.get('recall', 0):.2%}")
            print(f"  Threshold: {data.get('threshold', 0):.3f}")
            return True
    except Exception as e:
        print(f"✗ API Server not responding: {e}")
        return False

def score_url(url):
    """Score a single URL via API."""
    try:
        # For simplicity, send basic features structure
        # In real extension, this comes from content.js
        payload = {
            "url": url,
            "features": {
                "url_length": len(url),
                "domain_length": len(url.split("://")[1].split("/")[0]) if "/" in url.split("://")[1] else len(url.split("://")[1]),
                "subdomain_count": url.split("://")[1].split("/")[0].count(".") - 1 if "." in url else 0,
                "dot_count": url.count("."),
                "dash_count": url.count("-"),
                "underscore_count": url.count("_"),
                "percent_count": url.count("%"),
                "digit_ratio": sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
                "has_at": 1 if "@" in url else 0,
                "has_http": 1 if "http://" in url else 0,
                "has_https": 1 if "https://" in url else 0,
                "is_ip_address": 1 if all(x.isdigit() or x == "." for x in url.split("://")[1].split("/")[0]) else 0,
                "is_ipv4": 0,  # Simplified
                "is_ipv6": 0,  # Simplified
                "suspicious_tld": 1 if any(url.endswith(tld) for tld in [".tk", ".ml", ".ga", ".xyz", ".top"]) else 0,
                "tld_length": 0,  # Would extract from URL
                "double_slash_count": 0,
                "has_suspicious_words": 1 if any(word in url.lower() for word in ["verify", "confirm", "update", "login", "password"]) else 0,
                "suspicious_word_count": sum(1 for word in ["verify", "confirm", "update", "login", "password"] if word in url.lower()),
                "entropy_domain": 0,
                "entropy_url": 0,
                "path_length": len(url.split("/", 3)[3]) if url.count("/") > 2 else 0,
                "parameter_count": url.count("&") + url.count("="),
                "has_port": 1 if ":" in url.split("://")[1].split("/")[0] else 0,
                "in_whitelist": 0,
            }
        }
        
        response = requests.post(API_URL, json=payload, timeout=5)
        if response.status_code == 200:
            result = response.json()
            return {
                "url": url,
                "probability": result.get("probability", 0),
                "is_phishing": result.get("is_phishing", False),
                "decision": result.get("decision", "UNKNOWN"),
                "confidence": result.get("confidence", 0),
                "success": True,
            }
    except Exception as e:
        print(f"  Error: {e}")
    
    return {
        "url": url,
        "success": False,
        "error": str(e),
    }

def test_urls(url_list, label, expected_phishing=None):
    """Test a list of URLs and report results."""
    print(f"\n{'='*70}")
    print(f"Testing: {label}")
    print(f"{'='*70}")
    print(f"URLs: {len(url_list)}")
    
    results = []
    correct = 0
    total = len(url_list)
    
    for url in url_list:
        result = score_url(url)
        results.append(result)
        
        if result["success"]:
            probability = result["probability"]
            is_phishing = result["is_phishing"]
            
            # Check correctness if expected label provided
            if expected_phishing is not None:
                is_correct = (is_phishing == expected_phishing)
                if is_correct:
                    correct += 1
                status = "✓" if is_correct else "✗"
            else:
                status = "ℹ"
            
            print(f"{status} {url:60} → {probability:.2%} ({result['decision']})")
        else:
            print(f"✗ {url:60} → ERROR")
    
    # Summary
    if expected_phishing is not None:
        accuracy = correct / total * 100 if total > 0 else 0
        print(f"\nAccuracy: {accuracy:.1f}% ({correct}/{total} correct)")
        return accuracy, results
    else:
        return None, results

# ─── Main Test Suite ──────────────────────────────────────────────────────────

def main():
    print("\n" + "="*70)
    print("🔍 Phishing Detector - Real Website Testing")
    print("="*70)
    
    # Check API availability
    if not check_api_health():
        print("\n❌ API server is not running!")
        print("Start it with: python api_server.py")
        return
    
    # Run test suites
    legit_acc, legit_results = test_urls(
        LEGITIMATE_URLS,
        "LEGITIMATE WEBSITES (expect low scores)",
        expected_phishing=False
    )
    
    phishing_acc, phishing_results = test_urls(
        PHISHING_URLS,
        "PHISHING PATTERNS (expect high scores)",
        expected_phishing=True
    )
    
    edge_acc, edge_results = test_urls(
        EDGE_CASES,
        "EDGE CASES (uncertain expectations)",
        expected_phishing=None
    )
    
    # Overall statistics
    print(f"\n{'='*70}")
    print("📊 OVERALL RESULTS")
    print(f"{'='*70}")
    
    if legit_acc is not None:
        print(f"Legitimate URLs Accuracy:  {legit_acc:.1f}%")
    
    if phishing_acc is not None:
        print(f"Phishing URLs Accuracy:    {phishing_acc:.1f}%")
    
    if legit_acc is not None and phishing_acc is not None:
        avg_acc = (legit_acc + phishing_acc) / 2
        print(f"Average Accuracy:          {avg_acc:.1f}%")
    
    # False positive rate
    false_positives = sum(1 for r in legit_results if r["success"] and r["is_phishing"])
    false_negatives = sum(1 for r in phishing_results if r["success"] and not r["is_phishing"])
    
    print(f"\nFalse Positives (legit marked as phishing): {false_positives}/{len(legit_results)}")
    print(f"False Negatives (phishing marked as legit): {false_negatives}/{len(phishing_results)}")
    
    if len(legit_results) > 0:
        fp_rate = false_positives / len(legit_results) * 100
        print(f"False Positive Rate: {fp_rate:.1f}%")
    
    if len(phishing_results) > 0:
        fn_rate = false_negatives / len(phishing_results) * 100
        print(f"False Negative Rate: {fn_rate:.1f}%")
    
    # Save results
    all_results = {
        "timestamp": time.time(),
        "legitimate": legit_results,
        "phishing": phishing_results,
        "edge_cases": edge_results,
        "metrics": {
            "legitimate_accuracy": legit_acc,
            "phishing_accuracy": phishing_acc,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
        }
    }
    
    results_file = Path(__file__).parent / "test_results.json"
    with open(results_file, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n✓ Results saved to: {results_file}")
    
    print(f"\n{'='*70}\n")

if __name__ == "__main__":
    main()
