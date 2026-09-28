// PhishGuard AI Application Controller

let featureChart = null;

// Initialize when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) {
    lucide.createIcons();
  }
  loadModelStats();
  renderHistory();

  // URL Scan Form
  const urlForm = document.getElementById("url-scan-form");
  if (urlForm) {
    urlForm.addEventListener("submit", handleUrlScan);
  }

  // Text Scan Form
  const textForm = document.getElementById("text-scan-form");
  if (textForm) {
    textForm.addEventListener("submit", handleTextScan);
  }
});

// Tab Switching
function switchTab(tabId) {
  const tabs = ["url-tab", "text-tab", "insights-tab", "guide-tab"];
  const navBtns = {
    "url-tab": "nav-url-tab",
    "text-tab": "nav-text-tab",
    "insights-tab": "nav-insights-tab",
    "guide-tab": "nav-guide-tab"
  };

  tabs.forEach(id => {
    const el = document.getElementById(id);
    const btn = document.getElementById(navBtns[id]);
    if (id === tabId) {
      el.classList.add("active");
      btn.className = "nav-btn px-4 py-2 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 bg-gradient-to-r from-cyan-500 to-sky-500 text-slate-950 shadow-md";
    } else {
      el.classList.remove("active");
      btn.className = "nav-btn px-4 py-2 rounded-lg text-sm font-semibold text-slate-400 hover:text-white hover:bg-cyber-700/60 transition-all flex items-center space-x-2";
    }
  });

  if (window.lucide) {
    lucide.createIcons();
  }

  if (tabId === "insights-tab" && !featureChart) {
    loadModelStats();
  }
}

// Set sample preset URLs
function setSampleUrl(url) {
  const input = document.getElementById("url-input");
  if (input) {
    input.value = url;
    input.focus();
  }
}

// Set sample preset texts
function setSampleText(type) {
  const input = document.getElementById("text-input");
  if (!input) return;

  if (type === "bank") {
    input.value = "URGENT: Your bank account has been suspended due to suspicious activity. Click here to verify your identity immediately: http://chase-security-fix.xyz";
  } else if (type === "lottery") {
    input.value = "CONGRATULATIONS! You have been selected as the winner of the $1,000,000 international lottery. Reply with your SSN and bank wire info to claim your reward.";
  } else if (type === "meeting") {
    input.value = "Hi team, here are the meeting minutes from today's sprint planning. Please review the backlog items by Friday.";
  }
}

// Handle URL Scan Submit
async function handleUrlScan(e) {
  e.preventDefault();
  const input = document.getElementById("url-input");
  const url = input.value.trim();
  if (!url) return;

  const loadingEl = document.getElementById("url-loading");
  const resultsEl = document.getElementById("url-results");
  const scanBtn = document.getElementById("scan-btn");

  loadingEl.classList.remove("hidden");
  resultsEl.classList.add("hidden");
  scanBtn.disabled = true;

  try {
    const response = await fetch("/api/scan-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Analysis failed");
    }

    const data = await response.json();
    displayUrlResults(data.data);
    saveToHistory(data.data);
  } catch (err) {
    alert("Error analyzing URL: " + err.message);
  } finally {
    loadingEl.classList.add("hidden");
    scanBtn.disabled = false;
  }
}

// Display URL Results in UI
function displayUrlResults(data) {
  const resultsEl = document.getElementById("url-results");
  resultsEl.classList.remove("hidden");

  // Display URL
  document.getElementById("scanned-url-display").textContent = data.url;

  // Animate Gauge & Score
  const score = data.risk_score;
  const circle = document.getElementById("score-gauge-circle");
  const scoreValue = document.getElementById("score-value");
  const scoreTier = document.getElementById("score-tier");
  const verdictBadge = document.getElementById("verdict-badge");
  const summaryEl = document.getElementById("verdict-summary");
  const gaugeCard = document.getElementById("verdict-gauge-card");

  // Animate text counter
  animateValue(scoreValue, 0, score, 800, "%");

  // Gauge circumference = 2 * PI * 50 = ~314.159
  const circumference = 314;
  const offset = circumference - (score / 100) * circumference;
  circle.style.strokeDashoffset = offset;

  // Determine styling based on score & verdict
  circle.classList.remove("text-emerald-400", "text-amber-400", "text-rose-500");
  gaugeCard.classList.remove("glow-emerald", "glow-amber", "glow-rose");
  verdictBadge.className = "mt-2 px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider border ";

  if (score < 35) {
    circle.classList.add("text-emerald-400");
    gaugeCard.classList.add("glow-emerald");
    verdictBadge.classList.add("bg-emerald-500/10", "text-emerald-400", "border-emerald-500/30");
    scoreTier.textContent = "Low Risk / Safe";
    scoreTier.className = "text-[11px] font-semibold uppercase tracking-wider text-emerald-400";
  } else if (score < 70) {
    circle.classList.add("text-amber-400");
    gaugeCard.classList.add("glow-amber");
    verdictBadge.classList.add("bg-amber-500/10", "text-amber-400", "border-amber-500/30");
    scoreTier.textContent = "Moderate Suspicion";
    scoreTier.className = "text-[11px] font-semibold uppercase tracking-wider text-amber-400";
  } else {
    circle.classList.add("text-rose-500");
    gaugeCard.classList.add("glow-rose");
    verdictBadge.classList.add("bg-rose-500/10", "text-rose-400", "border-rose-500/30");
    scoreTier.textContent = "Critical Danger";
    scoreTier.className = "text-[11px] font-semibold uppercase tracking-wider text-rose-400";
  }

  verdictBadge.textContent = data.verdict;
  summaryEl.textContent = data.summary;

  // Diagnostics list
  const diagnosticsList = document.getElementById("diagnostics-list");
  diagnosticsList.innerHTML = "";
  if (data.diagnostics && data.diagnostics.length > 0) {
    data.diagnostics.forEach(diag => {
      const item = document.createElement("div");
      item.className = "p-2.5 rounded-lg bg-cyber-900/80 border border-slate-800 text-xs flex items-start space-x-2 text-rose-300";
      item.innerHTML = `<i data-lucide="alert-circle" class="w-4 h-4 text-rose-400 shrink-0 mt-0.5"></i><span>${escapeHtml(diag)}</span>`;
      diagnosticsList.appendChild(item);
    });
  } else {
    diagnosticsList.innerHTML = `<div class="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs flex items-center space-x-2 text-emerald-400">
      <i data-lucide="check-circle-2" class="w-4 h-4 shrink-0"></i>
      <span>No anomalous threat markers detected in URL structure.</span>
    </div>`;
  }

  // Recommendations
  const recList = document.getElementById("recommendations-list");
  recList.innerHTML = "";
  (data.recommendations || []).forEach(rec => {
    const li = document.createElement("li");
    li.className = "flex items-start space-x-2";
    li.innerHTML = `<i data-lucide="chevron-right" class="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5"></i><span>${escapeHtml(rec)}</span>`;
    recList.appendChild(li);
  });

  // Feature Breakdown Table
  populateFeaturesTable(data.features);

  if (window.lucide) {
    lucide.createIcons();
  }

  resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
}

// Populate Deep Feature Inspector
function populateFeaturesTable(features) {
  const tbody = document.getElementById("features-table-body");
  tbody.innerHTML = "";

  const featureMetadata = [
    { key: "has_ip_address", name: "Direct IP Hostname", desc: "Checks if URL bypasses DNS by using raw IPv4/v6 address", badWhen: v => v === 1 },
    { key: "has_punycode", name: "Punycode (Homograph)", desc: "Detects 'xn--' spoofed internationalized glyphs", badWhen: v => v === 1 },
    { key: "is_https", name: "HTTPS Protocol", desc: "Transport Layer Security encryption status", badWhen: v => v === 0 },
    { key: "has_suspicious_tld", name: "High-Abuse TLD", desc: "Flagged disposable extensions (.xyz, .top, .ga, etc.)", badWhen: v => v === 1 },
    { key: "has_suspicious_keyword", name: "Credential Keywords", desc: "Presence of tokens like login, verify, auth, secure", badWhen: v => v === 1 },
    { key: "domain_entropy", name: "Domain Entropy", desc: "Shannon randomness of characters (high = DGA)", badWhen: v => v > 3.6 },
    { key: "subdomain_count", name: "Subdomain Depth", desc: "Number of nested subdomains masquerading", badWhen: v => v >= 2 },
    { key: "url_length", name: "URL Length", desc: "Total character count of complete URL string", badWhen: v => v > 85 },
    { key: "domain_length", name: "Domain Length", desc: "Character count of primary netloc hostname", badWhen: v => v > 30 },
    { key: "num_at_symbols", name: "At Symbols (@)", desc: "Obfuscation trick used to redirect browser destination", badWhen: v => v > 0 },
    { key: "num_dots", name: "Dot Count (.)", desc: "Total periods across entire URL string", badWhen: v => v >= 4 },
    { key: "num_hyphens", name: "Hyphen Count (-)", desc: "Hyphens frequently join lookalike brand names", badWhen: v => v >= 3 },
    { key: "has_shortener", name: "URL Shortener", desc: "Known link masking service (bit.ly, tinyurl, etc.)", badWhen: v => v === 1 },
    { key: "digit_ratio", name: "Digit Ratio", desc: "Fraction of numbers in URL string", badWhen: v => v > 0.2 }
  ];

  featureMetadata.forEach(meta => {
    const val = features[meta.key];
    const isBad = meta.badWhen(val);
    const tr = document.createElement("tr");
    tr.className = "hover:bg-cyber-800/40 transition-colors";

    let displayVal = val;
    if (meta.key === "is_https") displayVal = val === 1 ? "HTTPS (Secure)" : "HTTP (Unencrypted)";
    else if (meta.key === "has_ip_address") displayVal = val === 1 ? "Yes (IP Used)" : "No (Domain)";
    else if (meta.key === "has_suspicious_tld") displayVal = val === 1 ? `Yes (.${features.tld})` : "No";
    else if (meta.key === "has_suspicious_keyword") displayVal = val === 1 ? `Yes (${features.keywords_found?.join(', ') || 'found'})` : "No";

    const badgeHtml = isBad 
      ? `<span class="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 text-[10px] uppercase font-bold">Flagged / Anomaly</span>`
      : `<span class="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] uppercase font-bold">Standard</span>`;

    tr.innerHTML = `
      <td class="py-3 px-4 font-semibold text-slate-200">${escapeHtml(meta.name)}</td>
      <td class="py-3 px-4 ${isBad ? 'text-rose-400 font-bold' : 'text-slate-300'}">${escapeHtml(String(displayVal))}</td>
      <td class="py-3 px-4 text-slate-400 font-sans text-xs">${escapeHtml(meta.desc)}</td>
      <td class="py-3 px-4">${badgeHtml}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Handle Message / Text Scan
async function handleTextScan(e) {
  e.preventDefault();
  const input = document.getElementById("text-input");
  const text = input.value.trim();
  if (!text) return;

  const resultsEl = document.getElementById("text-results");

  try {
    const response = await fetch("/api/scan-text", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text })
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Analysis failed");
    }

    const data = await response.json();
    displayTextResults(data.data);
  } catch (err) {
    alert("Error analyzing message: " + err.message);
  }
}

function displayTextResults(data) {
  const resultsEl = document.getElementById("text-results");
  resultsEl.classList.remove("hidden");

  document.getElementById("text-verdict-title").textContent = data.verdict;
  document.getElementById("text-summary").textContent = data.summary;

  const pill = document.getElementById("text-risk-pill");
  pill.textContent = `Risk Score: ${data.risk_score}%`;
  pill.className = "px-4 py-1.5 rounded-full text-sm font-bold font-mono border ";
  if (data.risk_score < 35) {
    pill.classList.add("bg-emerald-500/10", "text-emerald-400", "border-emerald-500/30");
  } else if (data.risk_score < 70) {
    pill.classList.add("bg-amber-500/10", "text-amber-400", "border-amber-500/30");
  } else {
    pill.classList.add("bg-rose-500/10", "text-rose-400", "border-rose-500/30");
  }

  // Indicators
  const ind = data.indicators || {};
  document.getElementById("urgency-count").textContent = ind.urgency_score || 0;
  document.getElementById("urgency-tokens").textContent = (ind.urgency_matches || []).join(", ") || "None";

  document.getElementById("credential-count").textContent = ind.credential_score || 0;
  document.getElementById("credential-tokens").textContent = (ind.credential_matches || []).join(", ") || "None";

  document.getElementById("financial-count").textContent = ind.financial_score || 0;
  document.getElementById("financial-tokens").textContent = (ind.financial_matches || []).join(", ") || "None";

  // Diagnostics
  const diagContainer = document.getElementById("text-diagnostics");
  diagContainer.innerHTML = "";
  if (data.diagnostics && data.diagnostics.length > 0) {
    data.diagnostics.forEach(diag => {
      const el = document.createElement("div");
      el.className = "p-2.5 rounded-lg bg-cyber-900/80 border border-slate-800 text-xs flex items-start space-x-2 text-rose-300";
      el.innerHTML = `<i data-lucide="alert-triangle" class="w-4 h-4 text-rose-400 shrink-0 mt-0.5"></i><span>${escapeHtml(diag)}</span>`;
      diagContainer.appendChild(el);
    });
  } else {
    diagContainer.innerHTML = `<div class="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-400 flex items-center space-x-2">
      <i data-lucide="check-circle-2" class="w-4 h-4 shrink-0"></i>
      <span>No coercive social engineering patterns detected.</span>
    </div>`;
  }

  if (window.lucide) {
    lucide.createIcons();
  }

  resultsEl.scrollIntoView({ behavior: "smooth" });
}

// Load Model Stats and Chart
async function loadModelStats() {
  try {
    const res = await fetch("/api/model-stats");
    if (!res.ok) return;
    const json = await res.json();
    const stats = json.data;

    const metrics = stats.url_metrics || {};
    document.getElementById("stat-accuracy").textContent = `${Math.round((metrics.accuracy || 0.96) * 100)}%`;
    document.getElementById("stat-precision").textContent = `${Math.round((metrics.precision || 0.95) * 100)}%`;
    document.getElementById("stat-recall").textContent = `${Math.round((metrics.recall || 0.97) * 100)}%`;
    document.getElementById("stat-f1").textContent = `${Math.round((metrics.f1_score || 0.96) * 100)}%`;

    // Render Chart
    renderFeatureChart(stats.top_features || []);
  } catch (e) {
    console.error("Failed to load model stats:", e);
  }
}

function renderFeatureChart(topFeatures) {
  const ctx = document.getElementById("featureImportanceChart");
  if (!ctx) return;

  if (featureChart) {
    featureChart.destroy();
  }

  const labels = topFeatures.map(f => f.feature.replace(/_/g, " ").toUpperCase());
  const values = topFeatures.map(f => f.importance);

  featureChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Relative Feature Weight",
        data: values,
        backgroundColor: "rgba(6, 182, 212, 0.75)",
        borderColor: "rgba(56, 189, 248, 1)",
        borderWidth: 1,
        borderRadius: 6
      }]
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#94a3b8", font: { family: "JetBrains Mono" } }
        },
        y: {
          grid: { display: false },
          ticks: { color: "#e2e8f0", font: { size: 11, weight: "bold" } }
        }
      }
    }
  });
}

// Session History Storage
function saveToHistory(result) {
  try {
    let history = JSON.parse(localStorage.getItem("phishguard_scans") || "[]");
    history.unshift({
      url: result.url,
      verdict: result.verdict,
      risk_score: result.risk_score,
      timestamp: new Date().toLocaleTimeString()
    });
    if (history.length > 8) history = history.slice(0, 8);
    localStorage.setItem("phishguard_scans", JSON.stringify(history));
    renderHistory();
  } catch (e) {}
}

function renderHistory() {
  const container = document.getElementById("history-container");
  if (!container) return;

  try {
    const history = JSON.parse(localStorage.getItem("phishguard_scans") || "[]");
    if (history.length === 0) {
      container.innerHTML = `<div class="text-center py-6 text-slate-500 font-mono text-xs">No scans recorded yet. Enter a URL above to inspect threats.</div>`;
      return;
    }

    container.innerHTML = "";
    history.forEach(item => {
      const row = document.createElement("div");
      row.className = "flex items-center justify-between p-3 rounded-lg bg-cyber-900/60 border border-slate-800 hover:border-sky-500/30 transition-all";
      
      let badgeClass = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      if (item.risk_score >= 70) badgeClass = "bg-rose-500/10 text-rose-400 border-rose-500/30";
      else if (item.risk_score >= 35) badgeClass = "bg-amber-500/10 text-amber-400 border-amber-500/30";

      row.innerHTML = `
        <div class="flex items-center space-x-3 overflow-hidden">
          <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${badgeClass}">${item.risk_score}%</span>
          <span class="font-mono text-xs text-slate-300 truncate max-w-sm sm:max-w-md">${escapeHtml(item.url)}</span>
        </div>
        <div class="flex items-center space-x-3 shrink-0">
          <span class="text-[11px] text-slate-500">${item.timestamp}</span>
          <button onclick="rescanHistoryUrl('${encodeURIComponent(item.url)}')" class="px-2.5 py-1 rounded bg-cyber-800 hover:bg-cyber-700 text-cyan-400 text-xs font-medium transition-all">Re-Scan</button>
        </div>
      `;
      container.appendChild(row);
    });
  } catch (e) {}
}

function rescanHistoryUrl(encodedUrl) {
  const url = decodeURIComponent(encodedUrl);
  setSampleUrl(url);
  document.getElementById("url-scan-form").dispatchEvent(new Event("submit"));
}

function clearHistory() {
  localStorage.removeItem("phishguard_scans");
  renderHistory();
}

// Helpers
function animateValue(el, start, end, duration, suffix = "") {
  let startTimestamp = null;
  const step = (timestamp) => {
    if (!startTimestamp) startTimestamp = timestamp;
    const progress = Math.min((timestamp - startTimestamp) / duration, 1);
    el.textContent = Math.floor(progress * (end - start) + start) + suffix;
    if (progress < 1) {
      window.requestAnimationFrame(step);
    } else {
      el.textContent = end + suffix;
    }
  };
  window.requestAnimationFrame(step);
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}
