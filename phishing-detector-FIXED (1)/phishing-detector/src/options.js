/**
 * options.js — Phishing Guard — Command Centre
 * Cyberpunk red edition
 */

"use strict";

// ── Live clock ────────────────────────────────────────────────────────────────
function updateClock() {
  const el = document.getElementById("dashTime");
  if (el) el.textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
setInterval(updateClock, 1000);
updateClock();

// ── Navigation ────────────────────────────────────────────────────────────────
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`panel-${btn.dataset.panel}`).classList.add("active");
    if (btn.dataset.panel === "dashboard") initDashboard();
  });
});

// ── Custom toggle wiring ──────────────────────────────────────────────────────
document.querySelectorAll(".toggle-row").forEach((row) => {
  const input = row.querySelector(".toggle-input");
  const track = row.querySelector(".toggle-track");
  if (track && input) {
    track.addEventListener("click", () => {
      input.checked = !input.checked;
    });
  }
});

// ── Log Retrieval ─────────────────────────────────────────────────────────────
async function getLogs(from = null, to = null) {
  try {
    const response = await chrome.runtime.sendMessage({ type: "GET_LOGS", from, to });
    return response?.logs || [];
  } catch { return []; }
}

// ── Statistics ────────────────────────────────────────────────────────────────
function computeStats(logs) {
  const total      = logs.length;
  const suspicious = logs.filter((l) => l.riskScore >= 0.45).length;
  const high       = logs.filter((l) => l.riskScore >= 0.75).length;
  const safe       = total - suspicious;

  const dist = { "0–25%": 0, "25–50%": 0, "50–75%": 0, "75–100%": 0 };
  for (const l of logs) {
    const s = l.riskScore;
    if (s < 0.25)      dist["0–25%"]++;
    else if (s < 0.50) dist["25–50%"]++;
    else if (s < 0.75) dist["50–75%"]++;
    else               dist["75–100%"]++;
  }

  const domainFreq = {};
  for (const l of logs) {
    if (l.domain) domainFreq[l.domain] = (domainFreq[l.domain] || 0) + 1;
  }
  const topDomains = Object.entries(domainFreq).sort((a, b) => b[1] - a[1]).slice(0, 10);

  const byDay = {};
  for (const l of logs) {
    const day = new Date(l.timestamp).toLocaleDateString();
    byDay[day] = (byDay[day] || 0) + 1;
  }

  return { total, suspicious, high, safe, dist, topDomains, byDay };
}

// ── Chart instances ───────────────────────────────────────────────────────────
let chartDist, chartTimeline, chartDomains;
function destroyChart(c) { if (c) c.destroy(); }

// Chart.js global defaults — dark theme
const CHART_DEFAULTS = {
  color: "#8ab4cc",
  borderColor: "#0f1f2d",
};

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function initDashboard() {
  const logs  = await getLogs();
  const stats = computeStats(logs);

  // Stat cards
  setStatCard("statTotal",      stats.total,      false, stats.total);
  setStatCard("statSuspicious", stats.suspicious, true,  stats.total);
  setStatCard("statPhishing",   stats.high,       true,  stats.total);
  setStatCard("statSafe",       stats.safe,       false, stats.total);

  // Doughnut — risk distribution
  destroyChart(chartDist);
  chartDist = new Chart(document.getElementById("chartDistribution"), {
    type: "doughnut",
    data: {
      labels: Object.keys(stats.dist),
      datasets: [{
        data:            Object.values(stats.dist),
        backgroundColor: ["#00f5c3", "#ffaa00", "#ff7b2d", "#ff2d55"],
        borderColor:     "#000000",
        borderWidth:     3,
        hoverOffset:     6,
      }],
    },
    options: {
      plugins: {
        legend: {
          labels: { color: "#8ab4cc", font: { family: "Consolas", size: 11 }, padding: 14 },
        },
      },
      cutout: "65%",
    },
  });

  // Timeline — last 30 days
  const now         = Date.now();
  const recentLogs  = logs.filter((l) => l.timestamp >= now - 30 * 864e5);
  const recentStats = computeStats(recentLogs);

  const timeLabels = [], timeValues = [];
  for (let d = 29; d >= 0; d--) {
    const day = new Date(now - d * 864e5).toLocaleDateString();
    timeLabels.push(d % 5 === 0 ? day : "");
    timeValues.push(recentStats.byDay[day] || 0);
  }

  destroyChart(chartTimeline);
  chartTimeline = new Chart(document.getElementById("chartTimeline"), {
    type: "line",
    data: {
      labels: timeLabels,
      datasets: [{
        label:           "Threats",
        data:            timeValues,
        borderColor:     "#ff2d55",
        backgroundColor: "rgba(255,45,85,0.1)",
        borderWidth:     2,
        tension:         0.4,
        fill:            true,
        pointRadius:     3,
        pointBackgroundColor: "#ff2d55",
        pointBorderColor:     "#000",
        pointHoverRadius:     5,
      }],
    },
    options: {
      scales: {
        x: {
          ticks: { color: "#4a7a99", font: { family: "Consolas", size: 9 } },
          grid:  { color: "#0f1f2d" },
        },
        y: {
          ticks: { color: "#4a7a99", font: { family: "Consolas", size: 9 } },
          grid:  { color: "#0f1f2d" },
          beginAtZero: true,
        },
      },
      plugins: { legend: { display: false } },
    },
  });

  // Bar — top domains
  destroyChart(chartDomains);
  chartDomains = new Chart(document.getElementById("chartDomains"), {
    type: "bar",
    data: {
      labels: stats.topDomains.map((d) => d[0]),
      datasets: [{
        label:           "Detections",
        data:            stats.topDomains.map((d) => d[1]),
        backgroundColor: stats.topDomains.map((_, i) =>
          i === 0 ? "#ff2d55" : i < 3 ? "rgba(255,45,85,0.6)" : "rgba(255,45,85,0.3)"
        ),
        borderColor:     "transparent",
        borderRadius:    4,
      }],
    },
    options: {
      indexAxis: "y",
      scales: {
        x: {
          ticks: { color: "#4a7a99", font: { family: "Consolas", size: 9 } },
          grid:  { color: "#0f1f2d" },
          beginAtZero: true,
        },
        y: {
          ticks: { color: "#8ab4cc", font: { family: "Consolas", size: 10 } },
          grid:  { color: "transparent" },
        },
      },
      plugins: { legend: { display: false } },
    },
  });
}

function setStatCard(id, value, warnIfPositive, total) {
  const card = document.getElementById(id);
  if (!card) return;
  // Count-up animation
  countUp(card.querySelector(".stat-num"), value, 800);
  if (warnIfPositive && value > 0) card.classList.add("active");

  // Animate progress bar fill
  const fill = card.querySelector(".stat-bar-fill");
  if (fill && total > 0) {
    setTimeout(() => {
      fill.style.width = `${Math.round((value / total) * 100)}%`;
    }, 200);
  }
}

function countUp(el, target, duration) {
  if (!el) return;
  const start = performance.now();
  const from  = parseInt(el.textContent) || 0;
  function tick(now) {
    const t = Math.min((now - start) / duration, 1);
    const e = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(from + (target - from) * e);
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ── Report builder ────────────────────────────────────────────────────────────
function buildReportHTML(logs, title, period) {
  const stats = computeStats(logs);

  const rows = logs.sort((a, b) => b.riskScore - a.riskScore).map((l) => {
    const pct   = Math.round(l.riskScore * 100);
    const color = pct >= 75 ? "#ff2d55" : pct >= 45 ? "#ffaa00" : "#00f5c3";
    return `
      <tr>
        <td style="font-family:Consolas;font-size:10px;color:#4a7a99;">${new Date(l.timestamp).toLocaleString()}</td>
        <td class="url-cell" title="${escHtml(l.pageURL)}">${escHtml(truncate(l.pageURL, 55))}</td>
        <td style="color:#8ab4cc;">${escHtml(l.domain || "—")}</td>
        <td><span style="font-family:Consolas;font-weight:900;color:${color};">${pct}%</span></td>
        <td style="color:#4a7a99;">${escHtml(l.category || "—")}</td>
        <td style="color:#4a7a99;font-size:10px;">${escHtml((l.threats || []).slice(0, 3).join(", ") || "—")}</td>
      </tr>`;
  }).join("");

  return `
    <div class="report-header">
      <h3>${escHtml(title)}</h3>
      <p class="report-period">◈ PERIOD: ${escHtml(period)}</p>
    </div>
    <div class="report-summary">
      <span>Total <strong>${stats.total}</strong></span>
      <span>Suspicious <strong class="warn">${stats.suspicious}</strong></span>
      <span>High Risk <strong class="danger">${stats.high}</strong></span>
      <span>Safe <strong class="safe">${stats.safe}</strong></span>
    </div>
    ${logs.length === 0
      ? `<div class="empty-state"><div class="empty-icon">◎</div><p>NO EVENTS IN THIS PERIOD</p></div>`
      : `<div class="table-wrap">
           <table class="report-table">
             <thead><tr>
               <th>Timestamp</th><th>URL</th><th>Domain</th>
               <th>Risk</th><th>Category</th><th>Threats</th>
             </tr></thead>
             <tbody>${rows}</tbody>
           </table>
         </div>`
    }`;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function truncate(str, n) {
  return typeof str === "string" && str.length > n ? str.slice(0, n) + "…" : (str || "");
}

// ── Date ranges ───────────────────────────────────────────────────────────────
function dayRange(v)   {
  const d = new Date(v);
  return { from: new Date(v).setHours(0,0,0,0), to: new Date(v).setHours(23,59,59,999), label: new Date(v).toDateString() };
}
function weekRange(v)  {
  const s = new Date(v); s.setHours(0,0,0,0);
  const e = new Date(s); e.setDate(e.getDate()+6); e.setHours(23,59,59,999);
  return { from: s.getTime(), to: e.getTime(), label: `${s.toDateString()} — ${e.toDateString()}` };
}
function monthRange(v) {
  const [yr,mo] = v.split("-").map(Number);
  const s = new Date(yr,mo-1,1), e = new Date(yr,mo,0,23,59,59,999);
  return { from: s.getTime(), to: e.getTime(), label: s.toLocaleString("default",{month:"long",year:"numeric"}) };
}

// ── CSV / PDF export ──────────────────────────────────────────────────────────
function exportCSV(logs, filename) {
  const header = ["Timestamp","URL","Domain","RiskScore","Category","Threats","SuspiciousLinks"].join(",");
  const rows   = logs.map((l) => [
    new Date(l.timestamp).toISOString(),
    `"${(l.pageURL||"").replace(/"/g,'""')}"`,
    `"${(l.domain ||"").replace(/"/g,'""')}"`,
    (l.riskScore||0).toFixed(4),
    l.category||"",
    `"${(l.threats||[]).join("; ").replace(/"/g,'""')}"`,
    l.suspiciousCount||0,
  ].join(","));
  const blob = new Blob([[header,...rows].join("\n")], { type:"text/csv;charset=utf-8;" });
  downloadBlob(blob, filename);
}

function exportPDF(html, title) {
  const win = window.open("","_blank");
  win.document.write(`<!DOCTYPE html><html><head><meta charset="UTF-8"/><title>${escHtml(title)}</title>
    <style>
      body{font-family:Arial,sans-serif;font-size:12px;color:#111;background:#fff;}
      h3{color:#c0392b;font-family:Consolas;} table{width:100%;border-collapse:collapse;}
      th,td{border:1px solid #ddd;padding:5px 8px;text-align:left;}
      th{background:#1a1a2e;color:#fff;}
      tr:nth-child(even){background:#f9f9f9;}
      .warn{color:#e67e22;} .danger{color:#c0392b;} .safe{color:#27ae60;}
      .report-summary{margin:12px 0;display:flex;gap:20px;font-size:13px;}
      .report-summary span{padding:6px 12px;border:1px solid #ddd;border-radius:4px;}
      @media print{button{display:none;}}
    </style></head><body>
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;padding-bottom:12px;border-bottom:2px solid #c0392b;">
      <strong style="font-size:18px;color:#c0392b;font-family:Consolas;">PHISHINGGUARD</strong>
      <span style="color:#888;font-size:11px;">Generated: ${new Date().toLocaleString()}</span>
    </div>
    ${html}
    <script>window.onload=()=>{window.print();}<\/script></body></html>`);
  win.document.close();
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = Object.assign(document.createElement("a"), { href: url, download: filename });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

// ── Report wiring ─────────────────────────────────────────────────────────────
let currentReportLogs = [], currentReportHTML = "";

async function renderReport(outputEl, title, from, to, period) {
  outputEl.innerHTML = `<p class="loading">◈ LOADING DATA...</p>`;
  const logs = await getLogs(from, to);
  currentReportLogs = logs;
  currentReportHTML = buildReportHTML(logs, title, period);
  outputEl.innerHTML = currentReportHTML;
}

// Daily
document.getElementById("loadDaily").addEventListener("click", async () => {
  const val = document.getElementById("dailyDate").value;
  if (!val) return alert("Select a date.");
  const { from, to, label } = dayRange(val);
  await renderReport(document.getElementById("dailyOutput"), "Daily Security Report", from, to, label);
});
document.getElementById("exportDailyCSV").addEventListener("click", () => exportCSV(currentReportLogs, `padm-daily-${Date.now()}.csv`));
document.getElementById("exportDailyPDF").addEventListener("click", () => exportPDF(currentReportHTML, "PADM Daily Report"));

// Weekly
document.getElementById("loadWeekly").addEventListener("click", async () => {
  const val = document.getElementById("weeklyDate").value;
  if (!val) return alert("Select a start date.");
  const { from, to, label } = weekRange(val);
  await renderReport(document.getElementById("weeklyOutput"), "Weekly Security Report", from, to, label);
});
document.getElementById("exportWeeklyCSV").addEventListener("click", () => exportCSV(currentReportLogs, `padm-weekly-${Date.now()}.csv`));
document.getElementById("exportWeeklyPDF").addEventListener("click", () => exportPDF(currentReportHTML, "PADM Weekly Report"));

// Monthly
document.getElementById("loadMonthly").addEventListener("click", async () => {
  const val = document.getElementById("monthlyDate").value;
  if (!val) return alert("Select a month.");
  const { from, to, label } = monthRange(val);
  await renderReport(document.getElementById("monthlyOutput"), "Monthly Security Report", from, to, label);
});
document.getElementById("exportMonthlyCSV").addEventListener("click", () => exportCSV(currentReportLogs, `padm-monthly-${Date.now()}.csv`));
document.getElementById("exportMonthlyPDF").addEventListener("click", () => exportPDF(currentReportHTML, "PADM Monthly Report"));

// ── Settings ──────────────────────────────────────────────────────────────────
const threshHigh    = document.getElementById("threshHigh");
const threshMed     = document.getElementById("threshMed");
const threshHighVal = document.getElementById("threshHighVal");
const threshMedVal  = document.getElementById("threshMedVal");

threshHigh.addEventListener("input", () => { threshHighVal.textContent = threshHigh.value + "%"; });
threshMed.addEventListener("input",  () => { threshMedVal.textContent  = threshMed.value  + "%"; });

async function loadSettings() {
  const s = await chrome.storage.local.get(["threshHigh","threshMed","notifEnabled"]);
  if (s.threshHigh)    { threshHigh.value = s.threshHigh; threshHighVal.textContent = s.threshHigh + "%"; }
  if (s.threshMed)     { threshMed.value  = s.threshMed;  threshMedVal.textContent  = s.threshMed  + "%"; }
  if (s.notifEnabled !== undefined) document.getElementById("notifEnabled").checked = s.notifEnabled;
}

document.getElementById("saveSettings").addEventListener("click", async () => {
  await chrome.storage.local.set({
    threshHigh:   parseInt(threshHigh.value),
    threshMed:    parseInt(threshMed.value),
    notifEnabled: document.getElementById("notifEnabled").checked,
  });
  const btn = document.getElementById("saveSettings");
  const orig = btn.textContent;
  btn.textContent = "◈ SAVED!";
  btn.style.background = "#00f5c3";
  btn.style.color = "#000";
  setTimeout(() => { btn.textContent = orig; btn.style.background = ""; btn.style.color = ""; }, 1800);
});

document.getElementById("clearLogs").addEventListener("click", async () => {
  if (!confirm("Delete ALL detection logs permanently? This cannot be undone.")) return;
  const request = indexedDB.open("PhishingDetectorDB", 1);
  request.onsuccess = (e) => {
    const db = e.target.result;
    const tx = db.transaction("detectionLogs", "readwrite");
    tx.objectStore("detectionLogs").clear();
    tx.oncomplete = () => {
      alert("All logs deleted.");
      initDashboard();
    };
  };
});

// ── Init ──────────────────────────────────────────────────────────────────────
(async () => {
  await loadSettings();
  await initDashboard();

  const today = new Date().toISOString().split("T")[0];
  document.getElementById("dailyDate").value   = today;
  document.getElementById("weeklyDate").value  = today;
  document.getElementById("monthlyDate").value = today.slice(0, 7);
})();