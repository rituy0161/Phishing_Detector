#!/usr/bin/env python3
"""
Test phishing detection on known phishing URLs.
Shows which URLs are being detected and which are being missed.
"""

import requests
import json

# Test URLs (known phishing)
TEST_URLS = [
    "http://weizihua.github.io/MyEtherWallet/",
    "http://www.aposicilia.com/fr/",
    "http://landjugend-beckum.de/6/6/3/login.php",
    "https://imtokens.co/",
    "https://roblox.com.ge/games/134374929677249/Obby-Vibe-Zone-NEW-POSES?privateServerLinkCode=25600398208546000332254510437439",
    "http://steamcomunitiy.com/request/2749150025",
    "http://7v34564123.duckdns.org/",
    "https://virajor.github.io/netflix-india-clone/",
    "https://www.netflix-clone-nu-nine.vercel.app/",
    "http://gpwfk.wpdevcloud.com/",
    "http://globalmindsnetwork.com/login/Loginfirst.php",
    "https://my.commb.com.au.58e32-cba20-43cc-8fb3.app/",
    "http://kocoinloginx.webflow.io/",
    "https://www.roblox.com.gl/users/216537487122/profile",
    "http://netflixlanding.iamhimanshu.in/",
    "http://netflix-gui-clone.vercel.app/",
    "https://notafakedomain.org/landing/form/ced7c5cf-55f5-4a88-a52c-e8aaa16051f4",
]

API_URL = "http://localhost:5000/batch_predict"

print("=" * 80)
print("TESTING PHISHING URL DETECTION")
print("=" * 80)

try:
    response = requests.post(API_URL, json={"urls": TEST_URLS}, timeout=30)
    results = response.json()["results"]
    
    print(f"\nTested {len(TEST_URLS)} URLs")
    print("-" * 80)
    
    detected = 0
    missed = 0
    
    for i, (url, result) in enumerate(zip(TEST_URLS, results + [None] * len(TEST_URLS)), 1):
        if result is None:
            print(f"{i}. ❌ NO RESPONSE - {url}")
            continue
            
        score = result.get("probability", 0)
        is_phishing = score > 0.41  # Using model threshold
        
        if is_phishing:
            detected += 1
            status = "✅ DETECTED"
        else:
            missed += 1
            status = "❌ MISSED"
        
        print(f"{i:2d}. {status} (score: {score:.4f}) - {url[:60]}")
    
    print("-" * 80)
    print(f"\nRESULTS: {detected} detected, {missed} missed")
    print(f"Detection Rate: {detected}/{len(TEST_URLS)} = {100*detected/len(TEST_URLS):.1f}%")
    
except Exception as e:
    print(f"ERROR: {e}")
    print("\nMake sure API server is running: python python/api_server.py")
