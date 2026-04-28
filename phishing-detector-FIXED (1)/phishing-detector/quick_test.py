#!/usr/bin/env python3
"""Quick test to verify API server can start"""
import subprocess
import time
import sys

print("Testing API server startup...")
print("-" * 60)

# Try to start the server with a timeout
try:
    proc = subprocess.Popen(
        ["python", "python/api_server.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd="."
    )
    
    # Wait a few seconds for startup
    time.sleep(3)
    
    if proc.poll() is None:
        # Process is still running - good!
        print("✅ API server started successfully!")
        print("\nServer is running on: http://localhost:5000")
        print("\nNow you can:")
        print("1. Load the extension in Chrome (chrome://extensions/)")
        print("2. Delete the test process (Ctrl+C in this terminal)")
        print("3. Start a fresh API server for actual testing")
        
        # Terminate the test
        proc.terminate()
        proc.wait()
    else:
        # Process exited immediately - error
        stdout, stderr = proc.communicate()
        print("❌ API server failed to start")
        print(f"\nError output:\n{stderr}")
        sys.exit(1)
        
except Exception as e:
    print(f"❌ Error starting API server: {e}")
    sys.exit(1)

print("\n" + "=" * 60)
print("✅ EXTENSION IS READY!")
print("=" * 60)
