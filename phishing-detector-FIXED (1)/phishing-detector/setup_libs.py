#!/usr/bin/env python3
"""
setup_libs.py — Phishing Attack Detection Master
=================================================
Downloads TensorFlow.js and Chart.js into the extension's /libs/ folder.
Run this ONCE before loading the extension in Chrome.

Usage:
    python setup_libs.py

This script must be run from the ROOT of the extension folder
(the folder that contains manifest.json).
"""

import os
import sys
import urllib.request
import shutil

LIBS = [
    {
        "name": "TensorFlow.js",
        "url":  "https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@4.17.0/dist/tf.min.js",
        "dest": "libs/tf.min.js",
        "size_kb": "~1,200 KB",
    },
    {
        "name": "Chart.js",
        "url":  "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js",
        "dest": "libs/chart.min.js",
        "size_kb": "~200 KB",
    },
]

def download(name, url, dest, size_kb):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    print(f"\n  Downloading {name} ({size_kb}) ...")
    print(f"  URL  : {url}")
    print(f"  Dest : {dest}")
    try:
        with urllib.request.urlopen(url, timeout=60) as resp, \
             open(dest, "wb") as out:
            shutil.copyfileobj(resp, out)
        size = os.path.getsize(dest)
        print(f"  ✅  Saved {size:,} bytes → {dest}")
        return True
    except Exception as e:
        print(f"  ❌  Failed: {e}")
        return False

def main():
    # Make sure we're in the right folder
    if not os.path.exists("manifest.json"):
        print("\n❌  ERROR: manifest.json not found in current directory.")
        print("    Run this script from the extension root folder:")
        print("    cd phishing-detector")
        print("    python setup_libs.py")
        sys.exit(1)

    print("\n" + "="*55)
    print("  PADM — Library Setup")
    print("  Downloading local copies of TF.js and Chart.js")
    print("="*55)

    results = []
    for lib in LIBS:
        ok = download(**lib)
        results.append((lib["name"], ok))

    print("\n" + "="*55)
    print("  RESULTS")
    print("="*55)
    all_ok = True
    for name, ok in results:
        status = "✅  OK" if ok else "❌  FAILED"
        print(f"  {status}  {name}")
        if not ok:
            all_ok = False

    if all_ok:
        print("\n  ✅  All libraries downloaded successfully!")
        print("  Next steps:")
        print("    1. Open chrome://extensions")
        print("    2. Click the ↺ Reload button on the extension card")
        print("    3. Browse any page — the shield badge should appear")
    else:
        print("\n  ⚠️  Some downloads failed.")
        print("  Check your internet connection and try again.")
        print("  Or manually download and save the files:")
        for lib in LIBS:
            print(f"    {lib['url']}")
            print(f"    → save as: {lib['dest']}")
    print("="*55)

if __name__ == "__main__":
    main()
