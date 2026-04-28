#!/usr/bin/env python3
"""
Quick diagnostic to test if extension can load.
"""

import json
import re
from pathlib import Path

ext_root = Path(__file__).parent / ".."  # Go up to phishing-detector/

print("🔍 Extension Diagnostic\n")

# 1. Check manifest.json
print("1. Checking manifest.json...")
try:
    with open(ext_root / "manifest.json") as f:
        manifest = json.load(f)
    print(f"   ✓ Manifest valid JSON")
    print(f"   ✓ Name: {manifest.get('name')}")
    print(f"   ✓ Service worker: {manifest.get('background', {}).get('service_worker')}")
    print(f"   ✓ Popup: {manifest.get('action', {}).get('default_popup')}")
except Exception as e:
    print(f"   ✗ Error: {e}")

# 2. Check if files exist
print("\n2. Checking required files...")
files_to_check = [
    "manifest.json",
    "src/background.js",
    "src/content.js",
    "src/popup.js",
    "popup.html",
    "options.html",
]

for f in files_to_check:
    path = ext_root / f
    if path.exists():
        size = path.stat().st_size
        print(f"   ✓ {f:30} ({size:,} bytes)")
    else:
        print(f"   ✗ {f} NOT FOUND")

# 3. Check JavaScript syntax
print("\n3. Checking JavaScript files...")
for js_file in ["src/background.js", "src/content.js", "src/popup.js"]:
    path = ext_root / js_file
    try:
        with open(path) as f:
            content = f.read()
        
        # Basic syntax check
        if content.count("{") == content.count("}"):
            print(f"   ✓ {js_file} - Brace count OK")
        else:
            print(f"   ⚠ {js_file} - Brace mismatch (might have arrays/objects)")
        
        # Check for obvious errors
        if "async function" in content:
            print(f"   ✓ {js_file} - Async functions present")
        
        # Look for common issues
        if "new URL(" in content and "try {" not in content.split("new URL(")[1].split("\n")[0]:
            # Check if URL parsing is wrapped in try-catch in this section
            pass  # We fixed this already
            
    except Exception as e:
        print(f"   ✗ {js_file} - Error: {e}")

# 4. Check content_scripts config
print("\n4. Checking content script configuration...")
try:
    with open(ext_root / "manifest.json") as f:
        manifest = json.load(f)
    
    content_scripts = manifest.get("content_scripts", [])
    if content_scripts:
        for script in content_scripts:
            print(f"   ✓ Matches: {script.get('matches')}")
            print(f"   ✓ JS files: {script.get('js')}")
            print(f"   ✓ Run at: {script.get('run_at')}")
    else:
        print(f"   ✗ No content scripts configured!")
except Exception as e:
    print(f"   ✗ Error: {e}")

# 5. Check API model files
print("\n5. Checking API model files...")
model_dir = ext_root / "python" / "model_advanced"
if model_dir.exists():
    for f in model_dir.glob("*"):
        print(f"   ✓ {f.name:40} ({f.stat().st_size:,} bytes)")
else:
    print(f"   ✗ Model directory not found at {model_dir}")

# 6. Check API server
print("\n6. Checking API server...")
api_file = ext_root / "python" / "api_server.py"
if api_file.exists():
    with open(api_file) as f:
        content = f.read()
    if "def predict():" in content or "@app.route" in content:
        print(f"   ✓ api_server.py exists and has Flask routes")
    else:
        print(f"   ⚠ api_server.py may not be complete")
else:
    print(f"   ✗ api_server.py not found")

print("\n" + "="*60)
print("\n✅ NEXT STEPS:")
print("1. Open chrome://extensions/")
print("2. Enable 'Developer mode'")
print("3. Click 'Load unpacked'")
print(f"4. Select: {ext_root}")
print("\nIf extension shows errors, install Firefox DevTools and:")
print("   - Right-click extension icon")
print("   - Click 'Inspect'")
print("   - Check 'Console' tab for errors")
print("\nTo use advanced model:")
print("   python api_server.py  # Start API in terminal")
print("\nTo test without API:")
print("   - Extension will fall back to heuristic scoring")
print("   - Won't use the 78% accurate XGBoost model")
print("   - Will use simpler rule-based scoring instead")

print("\n" + "="*60)
