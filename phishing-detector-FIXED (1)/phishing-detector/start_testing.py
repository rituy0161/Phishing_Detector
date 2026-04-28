#!/usr/bin/env python3
"""
Quick start guide for testing the Phishing Detector Extension
"""

import subprocess
import time
import sys
import os

print("=" * 70)
print("PHISHING DETECTOR EXTENSION - QUICK START")
print("=" * 70)

# Check if API server exists
api_file = "python/api_server.py"
if not os.path.exists(api_file):
    print(f"\n⚠️  {api_file} not found!")
    print("   Please ensure the API server file exists.")
    sys.exit(1)

print("\n📋 STEP 1: Starting Flask API Server")
print("-" * 70)
print(f"Starting: python {api_file}")
print("Server will run on: http://localhost:5000")
print("\nServer output:")
print()

# Start the API server
try:
    # Use subprocess.Popen to keep it running
    process = subprocess.Popen(
        ["python", api_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    # Give it a moment to start
    print("Waiting for server to start...")
    time.sleep(2)
    
    if process.poll() is not None:
        # Process exited immediately
        print("⚠️  Server exited with error code:", process.returncode)
        print("Output:", process.stdout)
        sys.exit(1)
    
    print("✅ Server started successfully!")
    print("\n" + "=" * 70)
    print("📖 STEP 2: Load Extension in Chrome")
    print("-" * 70)
    print("1. Open: chrome://extensions/")
    print("2. Enable 'Developer mode' (top right)")
    print("3. Click 'Load unpacked'")
    print("4. Select this folder: phishing-detector/")
    print("5. The extension icon will appear in your toolbar")
    
    print("\n" + "=" * 70)
    print("🧪 STEP 3: Test the Extension")
    print("-" * 70)
    print("Visit these URLs to test:")
    print("  ✅ https://google.com  - Should show LOW RISK (green)")
    print("  ❌ http://suspicious.tk/verify - Should show HIGH RISK (red)")
    print("  ❌ http://192.168.1.1/admin - Should show HIGH RISK (IP address)")
    
    print("\n" + "=" * 70)
    print("📊 Expected Behavior")
    print("-" * 70)
    print("• Extension analyzes every URL on the page")
    print("• Shows risk score (0-100%) in popup")
    print("• Lists suspicious links found on the page")
    print("• Green badge = safe, Red badge = phishing")
    
    print("\n" + "=" * 70)
    print("🛑 STOPPING THE SERVER")
    print("-" * 70)
    print("When done testing, press Ctrl+C to stop the server")
    print("=" * 70 + "\n")
    
    # Keep the server running and show output
    try:
        for line in process.stdout:
            if line:
                print(f"[API] {line.rstrip()}")
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping server...")
        process.terminate()
        process.wait(timeout=5)
        print("✅ Server stopped")

except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
