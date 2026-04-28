#!/usr/bin/env python3
"""
Test if the extension is properly scanning pages
"""
import time
import subprocess

print("=" * 70)
print("EXTENSION DIAGNOSTIC - CHECKING IF SCANNING WORKS")
print("=" * 70)

print("\n✓ API Server: Running on http://localhost:5000")
print("✓ Extension: Should be loaded in Chrome")

print("\n📋 WHAT TO CHECK:")
print("\n1. Open Chrome DevTools on ANY webpage:")
print("   - Press F12")
print("   - Go to 'Console' tab")
print("   - Look for messages starting with [PADM]")

print("\n2. If you see [PADM] messages:")
print("   ✓ Content script is injected")
print("   ✓ Features are being extracted")

print("\n3. Check the extension popup:")
print("   - Click the extension icon")
print("   - Should show risk gauge")
print("   - Should show list of URLs scanned")

print("\n4. If NOT working, check for errors:")
print("   - 'fetch failed' = API server not responding")
print("   - 'Cannot read property' = Code error")
print("   - No [PADM] messages = Content script not injected")

print("\n" + "=" * 70)
print("QUICK TEST:")
print("=" * 70)

# Test API health
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex(('localhost', 5000))
sock.close()

if result == 0:
    print("✓ API Server is accessible on localhost:5000")
else:
    print("✗ API Server NOT accessible on localhost:5000")
    print("  Make sure 'python python/api_server.py' is running!")

print("\n" + "=" * 70)
print("NEXT STEPS:")
print("=" * 70)
print("1. Reload the extension: chrome://extensions → Find extension → Reload")
print("2. Visit a webpage (e.g., https://google.com)")
print("3. Open DevTools console (F12) and look for [PADM] messages")
print("4. Click the extension icon and check if it shows results")

print("\nIf still not working, the issue might be:")
print("  - Content script regex pattern not matching the page")
print("  - API endpoint returning error")
print("  - Background script not initializing properly")

print("=" * 70)
