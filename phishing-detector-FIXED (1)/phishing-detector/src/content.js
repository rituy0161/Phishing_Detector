/**
 * content.js -- Phishing Attack Detection Master (Advanced)
 * ----------------------------------------------------------
 * Runs in the context of every web page.
 * Extracts 27 engineered features for XGBoost classification.
 *
 * Responsibilities:
 *   1. Extract comprehensive URL features (27 total)
 *   2. Calculate entropy for domain and URL
 *   3. Detect suspicious patterns (TLDs, words, IP addresses)
 *   4. Extract form actions and detect mismatches
 *   5. Send features to background.js for API inference
 *
 * PRIVACY: No data is sent to any remote server.
 * All analysis is local, inside the browser.
 */

(function () {
  "use strict";

  // --- Configuration ----------------------------------------------------------

  /**
   * Suspicious TLDs commonly associated with phishing campaigns.
   * Source: PhishTank / APWG trend reports.
   */
  const SUSPICIOUS_TLDS = new Set([
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work",
    "date", "racing", "review", "win", "bid", "stream", "gdn", "link",
    "press", "download", "science", "party", "country", "webcam", "london",
    "ge", "py", "ua", "ps", "af", "ly", "gl", "kz", "bn", "cd", "gr",
    "vip", "cc", "shop", "ir", "st", "sbs", "cfd", "pages", "app", "site",
    "online", "live", "help", "info", "support", "net", "biz", "ws", "su",
  ]);

  /**
   * Suspicious keywords commonly found in phishing URLs.
   */
  const SUSPICIOUS_WORDS = [
    "account", "confirm", "verify", "update", "login", "signin",
    "password", "secure", "bank", "amazon", "apple", "microsoft",
    "paypal", "download", "click", "alert", "warning", "expire",
    "suspended", "locked", "unusual", "activity", "action", "urgent",
    "clone", "copy", "fake", "test", "demo", "backup", "recovery",
    "bypass", "vault", "wallet", "crypto", "token", "exchange",
  ];

  /**
   * Whitelisted (trusted) domains that should never flag as phishing.
   */
  const WHITELIST_DOMAINS = new Set([
    "google.com", "amazon.com", "microsoft.com", "apple.com",
    "facebook.com", "twitter.com", "linkedin.com", "github.com",
    "wikipedia.org", "reddit.com", "youtube.com", "instagram.com",
    "netflix.com", "paypal.com", "ebay.com", "yahoo.com",
    "bing.com", "stackoverflow.com", "wordpress.com", "medium.com",
    "twitch.tv", "discord.com", "slack.com", "zoom.us",
  ]);

  /**
   * Suspicious hosting platforms commonly abused for phishing.
   */
  const SUSPICIOUS_HOSTS = new Set([
    "vercel.app", "netlify.app", "webflow.io", "github.io",
    "duckdns.org", "framer.app", "pages.dev", "weebly.com",
    "wixsite.com", "blogspot.com", "replit.com", "heroku.com",
    "fly.dev", "render.com", "railway.app", "glitch.me",
    "github.io", "gitpages.com", "gitbook.io", "my.id",
  ]);

  // --- Helper Functions -------------------------------------------------------

  /**
   * Safely parse a URL string; return null on failure.
   */
  function safeURL(raw) {
    try {
      return new URL(raw, window.location.href);
    } catch (_) {
      return null;
    }
  }

  /**
   * Calculate Shannon entropy of a string (randomness indicator).
   * Higher entropy = more random = more suspicious.
   */
  function calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in freq) {
      const p = freq[char] / str.length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Count occurrences of suspicious words in a string.
   */
  function countSuspiciousWords(str) {
    const lower = str.toLowerCase();
    let count = 0;
    for (const word of SUSPICIOUS_WORDS) {
      if (lower.includes(word)) count++;
    }
    return count;
  }

  /**
   * Check if a hostname is IPv4 address.
   */
  function isIPv4(hostname) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  }

  /**
   * Check if a hostname is IPv6 address.
   */
  function isIPv6(hostname) {
    return /^[\da-fA-F:]+$/.test(hostname) && hostname.includes(":");
  }

  /**
   * Extract TLD from hostname.
   */
  function getTLD(hostname) {
    const parts = hostname.split(".");
    return parts.length > 0 ? parts[parts.length - 1].toLowerCase() : "";
  }

  /**
   * Extract domain (second-level domain + TLD) from hostname.
   */
  function getDomain(hostname) {
    const parts = hostname.split(".");
    if (parts.length <= 2) return hostname;
    return parts.slice(-2).join(".");
  }

  /**
   * Extract the feature vector for a single URL.
   * Returns 27 features in the exact order expected by the model.
   *
   * Feature Order (CRITICAL - must match model training):
   *  0. url_length
   *  1. domain_length
   *  2. subdomain_count
   *  3. dot_count
   *  4. dash_count
   *  5. underscore_count
   *  6. percent_count
   *  7. digit_ratio
   *  8. has_at
   *  9. has_http
   * 10. has_https
   * 11. is_ip_address
   * 12. is_ipv4
   * 13. is_ipv6
   * 14. suspicious_tld
   * 15. tld_length
   * 16. double_slash_count
   * 17. has_suspicious_words
   * 18. suspicious_word_count
   * 19. entropy_domain
   * 20. entropy_url
   * 21. path_length
   * 22. parameter_count
   * 23. has_port
   * 24. in_whitelist
   */
  function extractAdvancedFeatures(rawURL) {
    const parsed = safeURL(rawURL);

    // Fallback for unparseable URLs
    if (!parsed) {
      return {
        url_length: Math.min(rawURL.length, 200),
        domain_length: 0,
        subdomain_count: 0,
        dot_count: (rawURL.match(/\./g) || []).length,
        dash_count: (rawURL.match(/-/g) || []).length,
        underscore_count: (rawURL.match(/_/g) || []).length,
        percent_count: (rawURL.match(/%/g) || []).length,
        digit_ratio: 0,
        has_at: rawURL.includes("@") ? 1 : 0,
        has_http: rawURL.includes("http://") ? 1 : 0,
        has_https: rawURL.includes("https://") ? 1 : 0,
        is_ip_address: 0,
        is_ipv4: 0,
        is_ipv6: 0,
        suspicious_tld: 1,
        tld_length: 0,
        double_slash_count: (rawURL.match(/\/\//g) || []).length,
        has_suspicious_words: 0,
        suspicious_word_count: 0,
        entropy_domain: 0,
        entropy_url: calculateEntropy(rawURL),
        path_length: 0,
        parameter_count: 0,
        has_port: 0,
        in_whitelist: 0,
      };
    }

    const hostname = parsed.hostname;
    const domain = getDomain(hostname);
    const tld = getTLD(hostname);
    const path = parsed.pathname;
    const search = parsed.search;

    // Basic counts
    const urlLength = rawURL.length;
    const domainLength = domain.length;
    const subdomainCount = hostname.split(".").length - 2;
    const dotCount = (hostname.match(/\./g) || []).length;
    const dashCount = (rawURL.match(/-/g) || []).length;
    const underscoreCount = (rawURL.match(/_/g) || []).length;
    const percentCount = (rawURL.match(/%/g) || []).length;
    const digitCount = (rawURL.match(/\d/g) || []).length;
    const digitRatio = urlLength > 0 ? digitCount / urlLength : 0;

    // Protocol checks
    const hasAt = rawURL.includes("@") ? 1 : 0;
    const hasHttp = parsed.protocol === "http:" ? 1 : 0;
    const hasHttps = parsed.protocol === "https:" ? 1 : 0;

    // IP address checks
    const ipv4Check = isIPv4(hostname) ? 1 : 0;
    const ipv6Check = isIPv6(hostname) ? 1 : 0;
    const isIPAddress = (ipv4Check || ipv6Check) ? 1 : 0;

    // TLD analysis
    const suspiciousTLD = SUSPICIOUS_TLDS.has(tld.toLowerCase()) ? 1 : 0;
    const tldLength = tld.length;

    // Path and parameter analysis
    const doubleSlashCount = (rawURL.match(/\/\//g) || []).length - 1; // -1 for protocol://
    const pathLength = path.length;
    const parameterCount = (search.match(/&|=|\?/g) || []).length;
    const hasPort = parsed.port ? 1 : 0;

    // Suspicious patterns
    const suspiciousWordCount = countSuspiciousWords(rawURL);
    const hasSuspiciousWords = suspiciousWordCount > 0 ? 1 : 0;

    // Entropy measures (randomness)
    const entropyDomain = calculateEntropy(domain);
    const entropyUrl = calculateEntropy(rawURL);

    // Whitelist check
    const inWhitelist = WHITELIST_DOMAINS.has(domain.toLowerCase()) ? 1 : 0;

    // Return features in exact order for model (27 features total)
    return {
      url_length: Math.min(urlLength, 26000), // Cap at reasonable max
      domain_length: domainLength,
      subdomain_count: subdomainCount,
      dot_count: dotCount,
      dash_count: dashCount,
      underscore_count: underscoreCount,
      percent_count: percentCount,
      digit_ratio: Math.min(digitRatio, 1.0),
      has_at: hasAt,
      has_http: hasHttp,
      has_https: hasHttps,
      is_ip_address: isIPAddress,
      is_ipv4: ipv4Check,
      is_ipv6: ipv6Check,
      suspicious_tld: suspiciousTLD,
      tld_length: tldLength,
      double_slash_count: doubleSlashCount,
      has_suspicious_words: hasSuspiciousWords,
      suspicious_word_count: suspiciousWordCount,
      entropy_domain: entropyDomain,
      entropy_url: entropyUrl,
      path_length: pathLength,
      parameter_count: parameterCount,
      has_port: hasPort,
      in_whitelist: inWhitelist,
      is_https: hasHttps,
      is_http: hasHttp,
    };
  }

  // --- Page Analysis Functions ------------------------------------------------

  /**
   * Collect all unique anchor href values from the page.
   */
  function collectAnchors() {
    const anchors = document.querySelectorAll("a[href]");
    console.log("[PADM] Found", anchors.length, "anchor elements on page");
    
    const seen = new Set();
    const urls = [];

    for (const a of anchors) {
      const href = a.getAttribute("href");
      if (!href || href.startsWith("#") || /^(javascript|mailto|tel):/i.test(href)) {
        continue;
      }
      const abs = safeURL(href);
      if (abs && !seen.has(abs.href)) {
        seen.add(abs.href);
        urls.push(abs.href);
      }
    }
    
    console.log("[PADM] Collected", urls.length, "valid anchor URLs");
    return urls;
  }

  /**
   * Extract form action URLs.
   */
  function extractFormActions() {
    const actions = [];
    document.querySelectorAll("form[action]").forEach((form) => {
      const action = safeURL(form.getAttribute("action"));
      if (action) {
        actions.push(action.href);
      }
    });
    return actions;
  }

  /**
   * Main extraction pipeline.
   */
  function runExtraction() {
    console.log("[PADM] runExtraction called on:", window.location.href);
    
    const anchorURLs = collectAnchors();
    const formActions = extractFormActions();
    const allURLs = [...new Set([...anchorURLs, ...formActions])];

    console.log("[PADM] Found", anchorURLs.length, "anchors and", formActions.length, "form actions = ", allURLs.length, "total URLs");

    // Extract features for all URLs
    const featureVectors = allURLs.map((url) => ({
      url,
      features: extractAdvancedFeatures(url),
    }));

    // Build payload for background.js
    const payload = {
      type: "PAGE_SCAN_ADVANCED",
      pageURL: window.location.href,
      pageTitle: document.title,
      timestamp: Date.now(),
      featureVectors,
      urlCount: allURLs.length,
    };

    console.log("[PADM] Sending PAGE_SCAN_ADVANCED with", allURLs.length, "URLs to background.js");
    
    // Send to background.js for API inference
    chrome.runtime.sendMessage(payload).catch((err) => {
      console.warn("[PADM] Failed to send message to background.js:", err.message);
    });
  }

  // --- Alert System -----------------------------------------------------------

  /**
   * Listen for phishing alerts from background.js.
   */
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "PHISHING_ALERT") {
      showWarningBanner(message);
    }
  });

  /**
   * Inject a dismissible warning banner.
   */
  function showWarningBanner(alert) {
    if (document.getElementById("padm-warning-banner")) return;

    const pct = Math.round((alert.probability || 0) * 100);
    const color = pct >= 75 ? "#c0392b" : pct >= 50 ? "#e67e22" : "#f39c12";
    const icon = pct >= 75 ? "🚨" : "⚠️";

    const banner = document.createElement("div");
    banner.id = "padm-warning-banner";
    banner.setAttribute("role", "alert");
    banner.style.cssText = `
      position: fixed; top: 0; left: 0; width: 100%; z-index: 2147483647;
      background: ${color}; color: #fff; font-family: system-ui, -apple-system;
      font-size: 14px; padding: 12px 16px; display: flex; align-items: center;
      justify-content: space-between; box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    `;

    const msg = document.createElement("span");
    msg.innerHTML = `${icon} <strong>Phishing Risk (${pct}%)</strong> -- URL: <code style="background:rgba(0,0,0,0.2);padding:2px 6px;border-radius:3px">${
      alert.url ? alert.url.substring(0, 60) + "..." : "Suspicious"
    }</code>`;

    const closeBtn = document.createElement("button");
    closeBtn.textContent = "✕";
    closeBtn.style.cssText = `
      background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.5);
      color: #fff; padding: 6px 12px; border-radius: 4px; cursor: pointer;
      font-size: 16px; margin-left: 16px;
    `;
    closeBtn.addEventListener("click", () => banner.remove());

    banner.appendChild(msg);
    banner.appendChild(closeBtn);
    document.body.prepend(banner);
  }

  // --- Initialization ---------------------------------------------------------

  console.log("[PADM] Content script initialized on:", window.location.href);

  if (document.readyState === "loading") {
    console.log("[PADM] Document still loading, waiting for DOMContentLoaded...");
    document.addEventListener("DOMContentLoaded", runExtraction);
  } else {
    console.log("[PADM] Document already loaded, running extraction now");
    runExtraction();
  }

  // Re-run on SPA navigation
  let lastURL = window.location.href;
  const observer = new MutationObserver(() => {
    if (window.location.href !== lastURL) {
      lastURL = window.location.href;
      console.log("[PADM] URL changed, re-running extraction in 500ms");
      setTimeout(runExtraction, 500);
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();
