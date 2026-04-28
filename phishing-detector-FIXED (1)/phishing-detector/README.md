# 🛡️ Phishing Attack Detection Master
### Chrome Extension — Capstone Cybersecurity Project
*Manifest V3 · TensorFlow.js · IndexedDB · Vanilla JavaScript*

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Folder Structure](#2-folder-structure)
3. [Architecture Explanation](#3-architecture-explanation)
4. [Data Flow](#4-data-flow)
5. [AI / ML Integration](#5-ai--ml-integration)
6. [Installation Instructions](#6-installation-instructions)
7. [Python Model Training](#7-python-model-training)
8. [Reporting System](#8-reporting-system)
9. [Security & Privacy Compliance](#9-security--privacy-compliance)
10. [Limitations](#10-limitations)
11. [Future Scope](#11-future-scope)

---

## 1. Project Overview

**Phishing Attack Detection Master (PADM)** is a production-grade Chrome extension that provides real-time phishing detection on any webpage — including Gmail and WhatsApp Web. All machine learning inference runs **locally inside the browser** using TensorFlow.js. No browsing data is ever transmitted to an external server.

### Key Capabilities
| Feature | Implementation |
|---|---|
| URL feature extraction | `content.js` DOM analysis |
| Local ML inference | TensorFlow.js neural network |
| Real-time page alerts | In-page warning banner |
| Desktop notifications | Chrome Notifications API |
| Detection logging | IndexedDB (client-side) |
| Daily/Weekly/Monthly reports | PDF + CSV export |
| Analytics dashboard | Chart.js visualisations |
| SPA support | MutationObserver (Gmail, WhatsApp) |

---

## 2. Folder Structure

```
phishing-detector/
├── manifest.json              # Chrome Extension Manifest V3
├── popup.html                 # Extension popup
├── options.html               # Reports & Settings page
│
├── src/
│   ├── content.js             # Page content scanner (runs on every page)
│   ├── background.js          # Service worker — ML inference, DB, alerts
│   ├── popup.js               # Popup UI controller
│   └── options.js             # Reports/settings UI controller
│
├── styles/
│   ├── popup.css              # Popup stylesheet (dark theme)
│   └── options.css            # Options page stylesheet
│
├── model/
│   ├── model.json             # TF.js model topology
│   └── group1-shard1of1.bin   # Model weights (replace with trained weights)
│
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
│
└── python/
    ├── train_model.py         # Full training, evaluation & export script
    └── sample_dataset.csv     # Dataset format reference + sample rows
```

---

## 3. Architecture Explanation

### content.js — Page Scanner
Injected into every page at `document_idle`. Extracts 10 features per URL and page-level signals:

```
DOM Analysis Pipeline
─────────────────────────────────────────────────
  querySelectorAll("a[href]")     → Collect all anchors
  querySelectorAll("form[action]")→ Detect cross-domain form actions
  querySelector('input[type=password]') → Password field detection
  querySelectorAll("iframe")      → Hidden iframe detection
  querySelectorAll("script[src]") → External script count
  MutationObserver                → SPA navigation detection (Gmail/WA)
─────────────────────────────────────────────────
        ↓
  chrome.runtime.sendMessage({ type: "PAGE_SCAN", ... })
```

### background.js — Service Worker
The brain of the extension. Handles all heavy computation:

```
Message received: PAGE_SCAN
─────────────────────────────────────────────────
  For each feature vector:
    1. normaliseFeatures()      → Min-max scale [0,1]
    2. tf.tensor2d([norm])      → Create TF tensor
    3. model.predict(input)     → Neural net inference
    4. score = output.dataSync()[0]  → Extract probability
  
  pageRiskScore = max(individual scores)
  
  if score ≥ 0.75:
    → logDetection(IndexedDB)
    → sendMessage("PHISHING_ALERT") → content.js
    → chrome.notifications.create()
  
  updateBadge(tabId, score)      → Green/Yellow/Red
  tabScanCache.set(tabId, result)
```

### popup.js — UI Controller
Queries background for current tab's scan result and renders:
- Animated SVG gauge (0–100% risk)
- 6 threat indicator chips (active/inactive)
- Sorted list of suspicious URLs with score bars
- Footer statistics

### options.js — Reports & Settings
Full reporting system with:
- Dashboard: 4 stat cards + 3 Chart.js charts
- Time-range queries via `GET_LOGS` message
- CSV generation (Blob download)
- PDF generation (print dialog)
- Settings persistence via `chrome.storage.local`

---

## 4. Data Flow

```
User browses to any page
         │
         ▼
┌─────────────────────────────────┐
│         content.js              │
│  • Extract URLs from anchors    │
│  • Detect forms, iframes, pwd  │
│  • Build 10-feature vectors     │
│  • sendMessage("PAGE_SCAN")     │
└────────────┬────────────────────┘
             │ chrome.runtime.sendMessage
             ▼
┌─────────────────────────────────┐
│        background.js            │
│  (Manifest V3 Service Worker)   │
│                                 │
│  1. Receive PAGE_SCAN           │
│  2. Normalise features          │
│  3. TensorFlow.js inference     │
│  4. Calculate risk score        │
│  5. Log to IndexedDB            │
│  6. Update badge                │
│  7. Send PHISHING_ALERT         │
└───────┬───────────────┬─────────┘
        │               │
        ▼               ▼
┌──────────────┐  ┌─────────────────────┐
│  popup.js    │  │   content.js (reply) │
│              │  │   showWarningBanner  │
│  GET_SCAN_   │  │   (injected DOM)     │
│  RESULT      │  └─────────────────────┘
│              │
│  Render:     │
│  • Gauge     │
│  • Chips     │
│  • Links     │
└──────────────┘

options.js ←──── GET_LOGS ────→ background.js ──→ IndexedDB
```

---

## 5. AI / ML Integration

### Feature Vector (10 Features)

| # | Feature | Type | Description |
|---|---------|------|-------------|
| 0 | `urlLength` | int | Total URL character length |
| 1 | `dotCount` | int | Count of `.` in hostname |
| 2 | `hasAt` | 0/1 | `@` symbol present in URL |
| 3 | `isHttps` | 0/1 | Protocol is HTTPS |
| 4 | `subdomainCount` | int | Subdomain depth |
| 5 | `isIPAddress` | 0/1 | Hostname is raw IP |
| 6 | `suspiciousTLD` | 0/1 | TLD in blocklist |
| 7 | `formActionMismatch` | 0/1 | Form submits cross-domain |
| 8 | `hasPasswordField` | 0/1 | Password input exists |
| 9 | `externalScriptCount` | int | External `<script>` count |

### Neural Network Architecture

```
Input Layer    [10 features]
      │
Dense(16, ReLU) + BatchNorm + Dropout(0.3)
      │
Dense(8, ReLU) + Dropout(0.2)
      │
Dense(1, Sigmoid) → Risk score ∈ [0, 1]
```

Total parameters: ~321 weights. Inference time: <1ms in browser.

### Normalisation
Min-max scaling applied per feature:
```
normalized = (value - feature_min) / (feature_max - feature_min)
```
Bounds are defined in `background.js` constants `FEATURE_MINS` / `FEATURE_MAXS`.
These must be updated when retraining with new data.

### Risk Thresholds
```
score ≥ 0.75  → HIGH RISK   (red badge, notification, page banner)
score ≥ 0.45  → MEDIUM RISK (yellow badge, logged)
score < 0.45  → SAFE        (green badge)
```

### Heuristic Fallback
If the model file is not present (e.g., during development), `background.js` falls back to a weighted heuristic scorer. This ensures the extension is functional without the trained model.

---

## 6. Installation Instructions

### Prerequisites
- Google Chrome 88+ (Manifest V3 support)
- Node.js 18+ (optional, for development only)

### Steps

**1. Clone / download the project**
```bash
git clone <your-repo> phishing-detector
cd phishing-detector
```

**2. Train and export the model** (see Section 7)
```bash
cd python
pip install tensorflow scikit-learn pandas tensorflowjs matplotlib seaborn
python train_model.py
cp -r tfjs_model/* ../model/
cd ..
```

**3. Add icons**
Place PNG icon files in `/icons/`:
- `icon16.png`  (16×16)
- `icon48.png`  (48×48)
- `icon128.png` (128×128)

**4. Load in Chrome**
1. Open `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `phishing-detector/` folder
5. The extension icon appears in the toolbar ✅

**5. Verify**
- Visit any webpage — the badge should show a green score
- Visit a known phishing test page (e.g., `http://216.58.xx.xx/login.php`) — badge should turn red

---

## 7. Python Model Training

```bash
cd python/

# Install dependencies
pip install tensorflow scikit-learn pandas tensorflowjs matplotlib seaborn

# Train with synthetic data (demo)
python train_model.py

# Train with your own dataset
python train_model.py --dataset your_dataset.csv --output ./my_model --epochs 100

# Output files:
#   tfjs_model/model.json          → copy to extension/model/
#   tfjs_model/group1-shard1of1.bin → copy to extension/model/
#   tfjs_model/normalisation_params.json → update background.js constants
#   confusion_matrix.png
#   training_history.png
```

### Recommended Real Datasets
| Dataset | URL |
|---------|-----|
| PhishTank | https://www.phishtank.com/developer_info.php |
| ISCX URL 2016 | https://www.unb.ca/cic/datasets/url-2016.html |
| OpenPhish | https://openphish.com/ |

### Expected Performance (with real data, ~50K samples)
| Metric | Expected Range |
|--------|---------------|
| Accuracy | 94–97% |
| Precision | 93–96% |
| Recall | 93–97% |
| ROC-AUC | 0.97–0.99 |

---

## 8. Reporting System

### IndexedDB Schema
```
Store: "detectionLogs"
Keys:   id (auto-increment)
Indexes: timestamp, domain, riskScore

Fields:
  pageURL        : string
  pageTitle      : string
  timestamp      : epoch ms
  riskScore      : float [0,1]
  category       : "safe" | "suspicious" | "phishing"
  domain         : string
  threats        : string[]
  suspiciousURLs : string[]
  totalLinks     : int
  suspiciousCount: int
```

### Report Generation
| Report | Period | Triggered by |
|--------|--------|--------------|
| Daily | Single calendar day | Date picker |
| Weekly | 7-day range | Week start picker |
| Monthly | Calendar month | Month picker |

### Export Formats
- **CSV**: RFC 4180 compliant, UTF-8, includes all fields
- **PDF**: Generated via print dialog (no external library needed)

---

## 9. Security & Privacy Compliance

### Data Collection
| Data Type | Collected? | Transmitted? |
|-----------|-----------|-------------|
| Page URLs | Yes (locally) | ❌ Never |
| Page content | No — only feature signals | ❌ Never |
| Personal data | ❌ Never | ❌ Never |
| Browsing history | ❌ Never | ❌ Never |
| User credentials | ❌ Never | ❌ Never |

### Manifest V3 Compliance
- Uses **service worker** (not persistent background page)
- No `eval()` or dynamic code execution
- No `unsafe-eval` in CSP (except `wasm-unsafe-eval` required by TF.js)
- `host_permissions` required for content script injection
- `activeTab` permission for badge updates

### Chrome Permissions Used
| Permission | Purpose |
|------------|---------|
| `activeTab` | Read current tab URL for badge |
| `scripting` | Inject content.js |
| `storage` | Persist user settings |
| `notifications` | High-risk desktop alerts |
| `alarms` | Periodic model reload |
| `<all_urls>` | Scan all pages (content script) |

### Local Storage Only
All detection logs are stored in the browser's **IndexedDB**, never synced to `chrome.storage.sync`, and never transmitted externally. Users can delete all logs at any time from the Settings panel.

---

## 10. Limitations

1. **Model Accuracy**: The placeholder model uses random weights. Accuracy depends entirely on training data quality and quantity. The heuristic fallback is used until trained weights are provided.

2. **Feature Coverage**: 10 features are a subset of possible phishing signals. Advanced evasion (legitimate-looking domains, HTTPS phishing) may evade detection.

3. **No URL Reputation API**: The extension cannot check URLs against real-time blocklists (PhishTank, Google Safe Browsing) without network requests, which would require user consent and a backend proxy.

4. **Service Worker Lifecycle**: Manifest V3 service workers can be killed by Chrome and restarted. The model is reloaded on restart, adding ~100ms latency to the first inference after sleep.

5. **Content Security Policy Conflicts**: Some pages with strict CSPs may interfere with the warning banner injection.

6. **SPA Detection Latency**: The 800ms MutationObserver debounce may miss very fast SPA transitions.

7. **No HTTPS Inspection**: The extension cannot inspect encrypted request payloads; analysis is limited to page structure and URLs.

8. **Obfuscated URLs**: Short URLs (bit.ly, tinyurl) are not followed or expanded (by design, for privacy). They appear as low-length, low-risk URLs.

---

## 11. Future Scope

| Enhancement | Description | Priority |
|-------------|-------------|---------|
| **URL Unshortening** | Safe local DNS lookup for short URLs | High |
| **Google Safe Browsing API** | Optional integration with user consent | High |
| **BERT/Transformer** | Replace simple NN with NLP model on URL text | Medium |
| **Visual Similarity** | Screenshot comparison for brand impersonation | Medium |
| **Crowdsourced Reporting** | Anonymous opt-in threat sharing | Medium |
| **Random Forest** | Ensemble model for better feature importance | Medium |
| **WHOIS Age Checking** | Flag newly registered domains | Low |
| **Certificate Transparency** | Detect suspicious TLS certificates | Low |
| **Firefox Port** | WebExtension API compatibility | Low |
| **CI/CD Pipeline** | Automated retraining on new phishing feeds | High |

---

## Architecture Decision Records

### Why Vanilla JS (no React/Vue)?
Manifest V3 extensions benefit from minimal bundle size. Vanilla JS eliminates build pipeline complexity, reduces attack surface, and loads faster. The popup renders in <50ms.

### Why TensorFlow.js over ONNX Runtime?
TF.js has better Chrome extension support, no WASM cross-origin restrictions for local inference, and well-documented Layers API for model export from Keras.

### Why IndexedDB over chrome.storage?
`chrome.storage.local` has a 10MB limit. IndexedDB supports gigabytes and provides indexed queries for efficient time-range reporting.

### Why Neural Network over Random Forest?
TF.js has native support for Keras Sequential models. Random forests require custom WASM bundles or approximation. A small NN achieves comparable accuracy with simpler deployment.

---

*Phishing Attack Detection Master — Capstone Cybersecurity Project*
*All analysis is performed locally. No data is ever transmitted.*
