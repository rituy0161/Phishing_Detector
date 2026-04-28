/**
 * background.js -- Phishing Attack Detection Master (Service Worker)
 * ------------------------------------------------------------------
 * Uses Flask API (XGBoost model) at localhost:5000 for inference.
 * Falls back to heuristic scoring if API is unavailable.
 *
 * PRIVACY: No data leaves the browser. All analysis is local.
 */

// --- API Configuration -------------------------------------------------------
// The Flask API server handles all ML inference
// If the server is not running, extension falls back to heuristic scoring
console.log("[PADM] Configured to use Flask API at http://localhost:5000");

// --- Constants ----------------------------------------------------------------

const RISK_THRESHOLD_HIGH   = 0.75;
const RISK_THRESHOLD_MEDIUM = 0.45;

const DB_NAME    = "PhishingDetectorDB";
const DB_VERSION = 1;
const STORE_NAME = "detectionLogs";

const MODEL_URL  = chrome.runtime.getURL("model/model.json");

// --- Feature Normalisation Bounds ---------------------------------------------
// Update these after training with train_phishtank.py
// (copy the values printed in the terminal under "COPY THESE INTO background.js")
const FEATURE_MINS = [12.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
const FEATURE_MAXS = [25523.0, 11.0, 1.0, 1.0, 10.0, 1.0, 1.0, 0.0, 0.0, 0.0];

// --- Global State -------------------------------------------------------------

var db          = null;
var tabScanCache = {};   // keyed by tabId

// --- IndexedDB ----------------------------------------------------------------

function openDatabase() {
  return new Promise(function(resolve, reject) {
    var req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = function(e) {
      var idb = e.target.result;
      if (!idb.objectStoreNames.contains(STORE_NAME)) {
        var store = idb.createObjectStore(STORE_NAME, { keyPath: "id", autoIncrement: true });
        store.createIndex("timestamp", "timestamp", { unique: false });
        store.createIndex("domain",    "domain",    { unique: false });
        store.createIndex("riskScore", "riskScore", { unique: false });
      }
    };

    req.onsuccess = function(e) { resolve(e.target.result); };
    req.onerror   = function(e) { reject(e.target.error);  };
  });
}

function logDetection(entry) {
  if (!db) return Promise.resolve();
  return new Promise(function(resolve, reject) {
    var tx    = db.transaction(STORE_NAME, "readwrite");
    var store = tx.objectStore(STORE_NAME);
    store.add(entry);
    tx.oncomplete = resolve;
    tx.onerror    = function(e) { reject(e.target.error); };
  });
}

function queryLogs(fromTS, toTS) {
  return new Promise(function(resolve, reject) {
    var tx    = db.transaction(STORE_NAME, "readonly");
    var store = tx.objectStore(STORE_NAME);
    var index = store.index("timestamp");
    var range = IDBKeyRange.bound(fromTS, toTS);
    var req   = index.getAll(range);
    req.onsuccess = function(e) { resolve(e.target.result); };
    req.onerror   = function(e) { reject(e.target.error);  };
  });
}

function queryAllLogs() {
  return new Promise(function(resolve, reject) {
    var tx  = db.transaction(STORE_NAME, "readonly");
    var req = tx.objectStore(STORE_NAME).getAll();
    req.onsuccess = function(e) { resolve(e.target.result); };
    req.onerror   = function(e) { reject(e.target.error);  };
  });
}

// --- Model Loading (removed - using Flask API) --------------------------------
// All model inference is now handled by the Flask API server

// --- Feature Normalisation ----------------------------------------------------

function normaliseFeatures(features) {
  var raw = [
    features.urlLength          || 0,
    features.dotCount           || 0,
    features.hasAt              || 0,
    features.isHttps            || 0,
    features.subdomainCount     || 0,
    features.isIPAddress        || 0,
    features.suspiciousTLD      || 0,
    features.formActionMismatch || 0,
    features.hasPasswordField   || 0,
    features.externalScriptCount|| 0,
  ];

  return raw.map(function(val, i) {
    var range = FEATURE_MAXS[i] - FEATURE_MINS[i];
    if (range === 0) return 0;
    return Math.min(1, Math.max(0, (val - FEATURE_MINS[i]) / range));
  });
}

// --- Inference ----------------------------------------------------------------

function predict(features) {
  var norm = normaliseFeatures(features);

  // -- TF.js neural network --------------------------------------------------
  if (model && typeof tf !== "undefined") {
    try {
      return tf.tidy(function() {
        var input  = tf.tensor2d([norm], [1, norm.length]);
        var output = model.predict(input);
        return output.dataSync()[0];
      });
    } catch (e) {
      console.warn("[PADM] Inference error, falling back to heuristic:", e.message);
    }
  }

  // -- Weighted heuristic fallback -------------------------------------------
  var weights = [0.08, 0.10, 0.15, -0.12, 0.12, 0.18, 0.14, 0.16, 0.05, 0.04];
  var score   = 0.10;
  for (var i = 0; i < norm.length; i++) {
    score += norm[i] * weights[i];
  }
  return Math.min(1, Math.max(0, score));
}

// --- Threat Labels ------------------------------------------------------------

function buildThreatLabels(features) {
  var labels = [];
  if (features.hasAt)               labels.push("@ symbol in URL");
  if (features.isIPAddress)         labels.push("IP address used as domain");
  if (features.suspiciousTLD)       labels.push("Suspicious TLD");
  if (features.formActionMismatch)  labels.push("Cross-domain form action");
  if (features.hasPasswordField)    labels.push("Password field detected");
  if (features.dotCount > 4)        labels.push("Excessive subdomains");
  if (features.urlLength > 100)     labels.push("Abnormally long URL");
  if (!features.isHttps)            labels.push("No HTTPS");
  if (features.externalScriptCount > 10) labels.push("High external script count");
  return labels;
}

// --- Badge --------------------------------------------------------------------

function updateBadge(tabId, score) {
  var pct   = Math.round(score * 100);
  var color = score >= RISK_THRESHOLD_HIGH   ? "#c0392b"
            : score >= RISK_THRESHOLD_MEDIUM ? "#e67e22"
            : "#27ae60";

  chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId }).catch(function(){});
  chrome.action.setBadgeText({ text: String(pct), tabId: tabId }).catch(function(){});
}

// --- Notification -------------------------------------------------------------

function notifyHighRisk(pageURL, riskScore, threats) {
  var pct = Math.round(riskScore * 100);
  var hostname = "unknown";
  try { hostname = new URL(pageURL).hostname; } catch(e){}

  chrome.notifications.create("padm-" + Date.now(), {
    type:     "basic",
    iconUrl:  chrome.runtime.getURL("icons/icon48.png"),
    title:    "\u26A0\uFE0F Phishing Risk: " + pct + "%",
    message:  hostname + "\n" + threats.slice(0, 2).join(" \u2022 "),
    priority: 2,
  });
}

// --- API Inference (Using Flask Backend) --------------------------------------

const API_ENDPOINT = "http://localhost:5000/predict";
const API_BATCH_ENDPOINT = "http://localhost:5000/batch_predict";

/**
 * Call the Flask API to score a URL's features.
 */
async function scoreWithAPI(urlString, features) {
  try {
    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlString, features: features }),
    });

    if (!response.ok) {
      console.warn("[PADM] API error:", response.status);
      return null;
    }

    const result = await response.json();
    return {
      probability: result.probability || 0,
      isPhishing: result.is_phishing || false,
      confidence: result.confidence || 0,
      decision: result.decision || "UNKNOWN",
    };
  } catch (error) {
    console.warn("[PADM] API call failed, falling back to heuristic:", error.message);
    return null;
  }
}

/**
 * Batch API scoring for multiple URLs.
 */
async function scoreWithAPIBatch(items) {
  console.log("[PADM] Calling API batch_predict with", items.length, "items");
  try {
    const response = await fetch(API_BATCH_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls: items }),
    });

    console.log("[PADM] API response status:", response.status);
    if (!response.ok) {
      console.warn("[PADM] API returned error status:", response.status);
      return null;
    }
    const result = await response.json();
    console.log("[PADM] API returned", result.results ? result.results.length : 0, "results");
    return result.results || [];
  } catch (error) {
    console.warn("[PADM] Batch API call failed:", error.message);
    return null;
  }
}

// --- Core Scan Handler (Advanced - with API) -----------------------------------

async function handlePageScanAdvanced(payload, tabId) {
  var pageURL = payload.pageURL;
  var pageTitle = payload.pageTitle;
  var timestamp = payload.timestamp;
  var featureVectors = payload.featureVectors || [];

  console.log("[PADM] handlePageScanAdvanced: Processing", featureVectors.length, "URLs from", pageURL);

  if (featureVectors.length === 0) {
    console.log("[PADM] No URLs to scan on:", pageURL);
    return;
  }

  var pageRiskScore = 0;
  var suspicious = [];
  var allResults = [];

  // Prepare batch request for API
  var apiItems = featureVectors.map(function(item) {
    return {
      url: item.url,
      features: item.features,
    };
  });

  // Try API first - if API is not running, fall back to heuristic
  var apiResults = await scoreWithAPIBatch(apiItems);

  if (apiResults && apiResults.length > 0) {
    // API scoring
    for (var i = 0; i < apiResults.length; i++) {
      var apiResult = apiResults[i];
      var url = apiResult.url || "unknown";
      var probability = apiResult.probability || 0;
      var isPhishing = apiResult.is_phishing || false;
      var hostname = "unknown";
      
      try {
        hostname = new URL(url).hostname;
      } catch (e) {
        // Keep hostname as "unknown"
      }

      var result = {
        url: url,
        hostname: hostname,
        score: probability,
        decision: apiResult.decision || "UNKNOWN",
        source: "api",
      };
      allResults.push(result);

      if (isPhishing || probability > 0.410) {
        suspicious.push(result);
      }
      pageRiskScore = Math.max(pageRiskScore, probability);
    }
    console.log("[PADM] Advanced model (API) scoring completed. Risk score:", pageRiskScore.toFixed(2));
  } else {
    // Fallback to simple heuristic if API unavailable
    console.warn("[PADM] API unavailable, using simple heuristic for scoring");
    for (var i = 0; i < featureVectors.length; i++) {
      var item = featureVectors[i];
      var features = item.features;
      
      // Simple heuristic scoring for 27-feature format
      var score = 0.2; // Base score
      
      // Add suspicious indicators
      if (features.suspicious_tld) score += 0.25;
      if (features.subdomain_count > 3) score += 0.15;
      if (features.is_ip_address) score += 0.20;
      if (features.has_at) score += 0.25;
      if (features.has_suspicious_words && features.suspicious_word_count > 0) score += 0.10 * features.suspicious_word_count;
      if (!features.has_https && features.has_http) score += 0.10;
      if (features.path_length > 200) score += 0.05;
      if (features.domain_length > 25) score += 0.05;
      
      score = Math.min(1, Math.max(0, score)); // Clamp 0-1
      var hostname = "unknown";
      
      try {
        hostname = new URL(item.url).hostname;
      } catch (e) {
        // Keep hostname as "unknown"
      }
      
      var result = {
        url: item.url,
        hostname: hostname,
        score: score,
        source: "heuristic",
      };
      allResults.push(result);

      if (score >= RISK_THRESHOLD_MEDIUM) {
        suspicious.push(result);
      }
      pageRiskScore = Math.max(pageRiskScore, score);
    }
  }

  pageRiskScore = Math.min(1, pageRiskScore);

  var category = "safe";
  if (pageRiskScore >= RISK_THRESHOLD_HIGH) category = "phishing";
  else if (pageRiskScore >= RISK_THRESHOLD_MEDIUM) category = "suspicious";

  var domain = "unknown";
  try { domain = new URL(pageURL).hostname; } catch(e){}

  var scanResult = {
    pageURL: pageURL,
    pageTitle: pageTitle,
    timestamp: timestamp,
    riskScore: pageRiskScore,
    category: category,
    suspicious: suspicious,
    allResults: allResults,
    totalLinks: featureVectors.length,
    domain: domain,
    model: "advanced",
  };

  tabScanCache[tabId] = scanResult;

  // Log if risky
  if (pageRiskScore >= RISK_THRESHOLD_MEDIUM) {
    await logDetection({
      pageURL: pageURL,
      pageTitle: pageTitle,
      timestamp: timestamp,
      riskScore: pageRiskScore,
      category: category,
      domain: domain,
      suspiciousCount: suspicious.length,
      totalLinks: featureVectors.length,
    });
  }

  // Alert if high risk
  if (pageRiskScore >= RISK_THRESHOLD_HIGH && suspicious.length > 0) {
    var topURL = suspicious[0].url;
    var topProbability = suspicious[0].score;
    chrome.tabs.sendMessage(tabId, {
      type: "PHISHING_ALERT",
      url: topURL,
      probability: topProbability,
    }).catch(function(){});
    notifyHighRisk(pageURL, pageRiskScore, [
      "Advanced XGBoost detection: " + Math.round(topProbability * 100) + "%"
    ]);
  }

  updateBadge(tabId, pageRiskScore);
}

// --- Core Scan Handler (Legacy) -----------------------------------------------

async function handlePageScan(payload, tabId) {
  var pageURL       = payload.pageURL;
  var pageTitle     = payload.pageTitle;
  var timestamp     = payload.timestamp;
  var featureVectors = payload.featureVectors || [];
  var pageContext   = payload.pageContext || {};

  var pageRiskScore = 0;
  var suspicious    = [];
  var allResults    = [];

  for (var i = 0; i < featureVectors.length; i++) {
    var features = featureVectors[i];
    var score    = predict(features);
    var result   = {
      url:     features.rawURL,
      hostname: features.hostname || "unknown",
      score:   score,
      threats: buildThreatLabels(features),
    };
    allResults.push(result);
    if (score >= RISK_THRESHOLD_MEDIUM) {
      suspicious.push(result);
    }
    if (score > pageRiskScore) pageRiskScore = score;
  }

  if (pageContext.formActionMismatch) pageRiskScore = Math.max(pageRiskScore, 0.55);
  if (pageContext.hasPasswordField && !pageURL.startsWith("https")) {
    pageRiskScore = Math.max(pageRiskScore, 0.65);
  }
  pageRiskScore = Math.min(1, pageRiskScore);

  var category = "safe";
  if (pageRiskScore >= RISK_THRESHOLD_HIGH)   category = "phishing";
  else if (pageRiskScore >= RISK_THRESHOLD_MEDIUM) category = "suspicious";

  var domain = "unknown";
  try { domain = new URL(pageURL).hostname; } catch(e){}

  var scanResult = {
    pageURL:    pageURL,
    pageTitle:  pageTitle,
    timestamp:  timestamp,
    riskScore:  pageRiskScore,
    category:   category,
    suspicious: suspicious,
    allResults: allResults,
    pageContext: pageContext,
    totalLinks: featureVectors.length,
    domain:     domain,
  };

  tabScanCache[tabId] = scanResult;

  if (pageRiskScore >= RISK_THRESHOLD_MEDIUM) {
    await logDetection({
      pageURL:        pageURL,
      pageTitle:      pageTitle,
      timestamp:      timestamp,
      riskScore:      pageRiskScore,
      category:       category,
      domain:         domain,
      threats:        suspicious.flatMap(function(s){ return s.threats; }),
      suspiciousURLs: suspicious.map(function(s){ return s.url; }),
      totalLinks:     featureVectors.length,
      suspiciousCount: suspicious.length,
    });
  }

  if (pageRiskScore >= RISK_THRESHOLD_HIGH) {
    var topThreats = suspicious.flatMap(function(s){ return s.threats; }).slice(0, 5);
    chrome.tabs.sendMessage(tabId, {
      type:      "PHISHING_ALERT",
      riskScore: pageRiskScore,
      threats:   topThreats,
    }).catch(function(){});
    notifyHighRisk(pageURL, pageRiskScore, topThreats);
  }

  updateBadge(tabId, pageRiskScore);
}

// --- Message Router -----------------------------------------------------------

chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
  var tabId = sender.tab ? sender.tab.id : null;

  console.log("[PADM] Message received:", message.type, "from tab", tabId);

  // Advanced model with API (new)
  if (message.type === "PAGE_SCAN_ADVANCED") {
    console.log("[PADM] Processing PAGE_SCAN_ADVANCED with", message.featureVectors.length, "URLs");
    handlePageScanAdvanced(message, tabId);
    sendResponse({ received: true });
    return false;
  }

  // Legacy model (TensorFlow.js)
  if (message.type === "PAGE_SCAN") {
    handlePageScan(message, tabId);
    sendResponse({ received: true });
    return false;
  }

  if (message.type === "GET_SCAN_RESULT") {
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      var id = tabs[0] ? tabs[0].id : null;
      sendResponse(tabScanCache[id] || null);
    });
    return true; // async
  }

  if (message.type === "GET_LOGS") {
    var from = message.from;
    var to   = message.to;
    var p    = (from && to) ? queryLogs(from, to) : queryAllLogs();
    p.then(function(logs) { sendResponse({ logs: logs }); })
     .catch(function(err)  { sendResponse({ error: err.message }); });
    return true; // async
  }

  sendResponse({ error: "Unknown message type" });
  return false;
});

// --- Initialisation -----------------------------------------------------------

(async function init() {
  db = await openDatabase();
  console.log("[PADM] Service worker initialised. Using Flask API at http://localhost:5000");
})();

chrome.runtime.onStartup.addListener(async function() {
  if (!db) db = await openDatabase();
});
