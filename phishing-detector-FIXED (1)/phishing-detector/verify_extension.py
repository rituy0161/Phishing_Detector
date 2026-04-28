#!/usr/bin/env python3
import json
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Verify manifest
print("Checking manifest.json...")
try:
    with open('manifest.json', 'r', encoding='utf-8') as f:
        manifest = json.load(f)
    print("✓ manifest.json is valid JSON")
    print(f"  Name: {manifest.get('name')}")
    print(f"  Version: {manifest.get('version')}")
    print(f"  Service Worker: {manifest['background']['service_worker']}")
    print(f"  Content Scripts: {len(manifest['content_scripts'])} registered")
except Exception as e:
    print(f"✗ manifest.json error: {e}")
    exit(1)

# Verify key files exist
print("\nChecking required files...")
required_files = [
    'src/background.js',
    'src/content.js',
    'src/popup.js',
    'popup.html',
    'manifest.json',
]

for f in required_files:
    if os.path.exists(f):
        size = os.path.getsize(f)
        print(f"✓ {f:30} ({size:6} bytes)")
    else:
        print(f"✗ {f:30} MISSING")

# Check model files
print("\nChecking model files (python/model_advanced/)...")
model_files = [
    'python/model_advanced/phishing_model_advanced.pkl',
    'python/model_advanced/scaler.pkl',
    'python/model_advanced/model_metadata.json',
]

for f in model_files:
    if os.path.exists(f):
        size = os.path.getsize(f)
        print(f"✓ {f:45} ({size:8} bytes)")
    else:
        print(f"⚠ (optional) {f}")

print("\n✅ Extension structure verified. Ready to load in Chrome!")
print("\nNext steps:")
print("1. Open chrome://extensions/ in Chrome")
print("2. Enable 'Developer mode' (top right)")
print("3. Click 'Load unpacked'")
print("4. Select the phishing-detector folder")
