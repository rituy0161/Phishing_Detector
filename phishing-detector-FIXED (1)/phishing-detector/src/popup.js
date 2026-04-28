/**
 * popup.js -- Phishing Attack Detection Master
 * Enhanced cyber HUD edition
 */

"use strict";

// ── DOM ───────────────────────────────────────────────────────────────────────
const gaugeArc      = document.getElementById("gaugeArc");
const gaugeText     = document.getElementById("gaugeText");
const riskLabel     = document.getElementById("riskLabel");
const riskSection   = document.getElementById("riskSection");
const statusDot     = document.getElementById("statusDot");
const statusBar     = document.getElementById("statusBar");
const indicatorGrid = document.getElementById("indicatorGrid");
const linkList      = document.getElementById("linkList");
const linkBadge     = document.getElementById("linkBadge");
const totalScanned  = document.getElementById("totalScanned");
const suspiciousCount = document.getElementById("suspiciousCount");
const scanTime      = document.getElementById("scanTime");

// ── Constants ─────────────────────────────────────────────────────────────────
const ARC_CIRC = 452; // 2 * PI * 72

const INDICATORS = [
  { key: "hasPasswordField",   label: "Password",    icon: "🔒" },
  { key: "formActionMismatch", label: "Form Mis.",   icon: "📋" },
  { key: "isIPAddress",        label: "IP Host",     icon: "🌐" },
  { key: "suspiciousTLD",      label: "Bad TLD",     icon: "🏷️" },
  { key: "hasAt",              label: "@ in URL",    icon: "＠" },
  { key: "hiddenIframes",      label: "iFrames",     icon: "🖼️" },
];

// ── Colour helpers ────────────────────────────────────────────────────────────
function riskColor(score) {
  if (score >= 0.75) return "#ff2d55";
  if (score >= 0.45) return "#ffaa00";
  return "#00f5c3";
}

function riskState(score) {
  if (score >= 0.75) return "danger";
  if (score >= 0.45) return "warn";
  return "safe";
}

function riskText(score) {
  if (score >= 0.75) return "⚠ HIGH RISK — LIKELY PHISHING";
  if (score >= 0.45) return "◈ MEDIUM RISK — SUSPICIOUS";
  return "✓ LOW RISK — LOOKS SAFE";
}

// ── Draw tick marks on gauge SVG ──────────────────────────────────────────────
function drawTicks() {
  const svg = document.querySelector(".gauge-svg");
  const g   = document.getElementById("ticks");
  if (!g) return;
  const cx = 100, cy = 100, r = 72;
  for (let i = 0; i <= 10; i++) {
    const angle  = Math.PI * (-0.05 + i * 0.11); // spread across 180°-ish
    const inner  = r - (i % 5 === 0 ? 10 : 6);
    const outer  = r + 2;
    const x1 = cx + outer * Math.cos(angle - Math.PI / 2);
    const y1 = cy + outer * Math.sin(angle - Math.PI / 2);
    const x2 = cx + inner * Math.cos(angle - Math.PI / 2);
    const y2 = cy + inner * Math.sin(angle - Math.PI / 2);
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", x1); line.setAttribute("y1", y1);
    line.setAttribute("x2", x2); line.setAttribute("y2", y2);
    line.setAttribute("stroke", i % 5 === 0 ? "#1f4a69" : "#152d40");
    line.setAttribute("stroke-width", i % 5 === 0 ? "1.5" : "1");
    g.appendChild(line);
  }
}

// ── Animate gauge ─────────────────────────────────────────────────────────────
function animateGauge(score) {
  const pct    = Math.round(score * 100);
  const color  = riskColor(score);
  const offset = ARC_CIRC - ARC_CIRC * score;
  const state  = riskState(score);

  // Arc
  gaugeArc.style.strokeDashoffset = offset;
  gaugeArc.style.stroke           = color;
  gaugeArc.style.filter           = `drop-shadow(0 0 8px ${color})`;

  // Center text — count up animation
  animateCount(gaugeText, pct, color);

  // Label
  riskLabel.textContent = riskText(score);
  riskLabel.style.color = color;

  // Status dot
  statusDot.style.background = color;
  statusDot.style.boxShadow  = `0 0 10px ${color}`;

  // Body state class
  document.body.className = `state-${state}`;

  // Status bar glow
  statusBar.style.borderColor = color;
  statusBar.style.boxShadow   = `0 0 14px rgba(${state === "danger" ? "255,45,85" : state === "warn" ? "255,170,0" : "0,245,195"},0.15)`;
}

function animateCount(el, target, color) {
  const duration = 1000;
  const start    = performance.now();
  const startVal = parseInt(el.textContent) || 0;

  function step(now) {
    const progress = Math.min((now - start) / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3);
    const val      = Math.round(startVal + (target - startVal) * eased);
    el.textContent = val + "%";
    el.style.fill  = color;
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ── Indicators ────────────────────────────────────────────────────────────────
function renderIndicators(pageContext, suspicious) {
  indicatorGrid.innerHTML = "";
  if (!Array.isArray(suspicious)) suspicious = [];

  const activeThreats = new Set(
    suspicious
      .flatMap(s => (s && s.threats) ? s.threats : [])
      .filter(t => typeof t === "string")
  );

  INDICATORS.forEach((ind, i) => {
    let active = false;
    if (ind.key in pageContext) {
      const v = pageContext[ind.key];
      active = Array.isArray(v) ? v.length > 0 : Boolean(v);
    }
    if (!active) {
      active = [...activeThreats].some(t =>
        t.toLowerCase().includes(ind.label.split(" ")[0].toLowerCase())
      );
    }

    const chip = document.createElement("div");
    chip.className = `indicator-chip ${active ? "active" : "inactive"}`;
    chip.title     = active ? "DETECTED" : "NOT DETECTED";
    chip.innerHTML = `<span class="ind-icon">${ind.icon}</span>
                      <span class="ind-label">${ind.label}</span>`;
    chip.style.animationDelay = `${i * 0.06}s`;
    indicatorGrid.appendChild(chip);
  });
}

// ── Link list ─────────────────────────────────────────────────────────────────
function renderLinks(suspicious) {
  if (!Array.isArray(suspicious)) suspicious = [];

  linkBadge.textContent = suspicious.length;
  linkBadge.style.display = suspicious.length === 0 ? "none" : "";

  if (suspicious.length === 0) {
    linkList.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">◎</div>
        <p>NO THREATS DETECTED</p>
      </div>`;
    return;
  }

  linkList.innerHTML = "";
  const sorted = [...suspicious].sort((a, b) => (b.score || 0) - (a.score || 0));

  sorted.forEach(link => {
    if (!link || typeof link.url !== "string") return;

    const pct   = Math.round((link.score || 0) * 100);
    const color = riskColor(link.score || 0);

    const item = document.createElement("div");
    item.className = "link-item";
    item.style.setProperty("--accent", color);

    const threats = (Array.isArray(link.threats) ? link.threats : [])
      .filter(Boolean).slice(0, 2).join("  ·  ");

    item.innerHTML = `
      <div class="score-bar">
        <div class="score-fill" style="width:${pct}%; background:${color}; color:${color};"></div>
      </div>
      <p class="link-url">${truncate(link.url, 52)}</p>
      <p class="link-meta" style="color:${color};">${pct}% RISK&nbsp;&nbsp;${threats || "suspicious pattern"}</p>`;

    linkList.appendChild(item);
  });
}

function truncate(str, n) {
  return typeof str === "string" && str.length > n ? str.slice(0, n) + "…" : (str || "");
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function renderPopup() {
  drawTicks();

  let result = null;
  try {
    result = await chrome.runtime.sendMessage({ type: "GET_SCAN_RESULT" });
  } catch (err) {
    console.warn("[PADM popup]", err.message);
  }

  if (!result || typeof result !== "object") {
    riskLabel.textContent = "BROWSE A PAGE TO BEGIN SCAN";
    riskLabel.style.color = "var(--text-muted)";
    gaugeText.textContent = "--";
    renderIndicators({}, []);
    return;
  }

  const score = typeof result.riskScore === "number" ? result.riskScore : 0;
  animateGauge(score);
  renderIndicators(result.pageContext || {}, result.suspicious || []);
  renderLinks(result.suspicious || []);

  // Stats
  totalScanned.textContent    = result.totalLinks || 0;
  suspiciousCount.textContent = (result.suspicious || []).length;

  if (result.timestamp) {
    const dt = new Date(result.timestamp);
    scanTime.textContent = dt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
}

document.addEventListener("DOMContentLoaded", renderPopup);