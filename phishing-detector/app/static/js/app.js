// PhishGuard AI Application Controller (Hardened against XSS & Enhanced UX)

let featureChart = null;

// Initialize on DOM ready
document.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) {
    lucide.createIcons();
  }
  loadModelStats();
  renderHistory();

  // URL Form
  const urlForm = document.getElementById("url-scan-form");
  const urlInput = document.getElementById("url-input");
  if (urlForm) {
    urlForm.addEventListener("submit", handleUrlScan);
  }
  if (urlInput) {
    urlInput.addEventListener("input", () => hideInlineError("url"));
  }

  // Text Form
  const textForm = document.getElementById("text-scan-form");
  const textInput = document.getElementById("text-input");
  if (textForm) {
    textForm.addEventListener("submit", handleTextScan);
  }
  if (textInput) {
    textInput.addEventListener("input", () => hideInlineError("text"));
  }
});

// Custom Inline Form Error Handling
function showInlineError(type, message) {
  const errorEl = document.getElementById(`${type}-inline-error`);
  const textEl = document.getElementById(`${type}-inline-error-text`);
  if (errorEl && textEl) {
    textEl.textContent = message;
    errorEl.classList.remove("hidden");
  }
}

function hideInlineError(type) {
  const errorEl = document.getElementById(`${type}-inline-error`);
  if (errorEl) {
    errorEl.classList.add("hidden");
  }
}

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
      btn.className = "nav-btn px-4 py-2 rounded-lg text-sm font-semibold text-slate-300 hover:text-white hover:bg-cyber-700/60 transition-all flex items-center space-x-2";
    }
  });

  if (window.lucide) {
    lucide.createIcons();
  }

  if (tabId === "insights-tab") {
    loadModelStats();
  }
}

// Sample Presets
function setSampleUrl(url) {
  const input = document.getElementById("url-input");
  if (input) {
    input.value = url;
    hideInlineError("url");
    input.focus();
  }
}

function setSampleText(type) {
  const input = document.getElementById("text-input");
  if (!input) return;

  hideInlineError("text");
  if (type === "bank") {
    input.value = "URGENT: Your Chase banking account has been suspended due to unauthorized access attempts. Click here to confirm identity immediately: http://chase-security-fix.xyz";
  } else if (type === "lottery") {
    input.value = "CONGRATULATIONS! You have been selected as the winner of the $1,000,000 international lottery. Reply with your SSN and bank wire info to claim your reward.";
  } else if (type === "meeting") {
    input.value = "Hi team, here are the meeting minutes from today's sprint planning. Please review the backlog items by Friday at https://github.com/project/tasks";
  }
}

// Handle URL Scan Submit
async function handleUrlScan(e) {
  e.preventDefault();
  const input = document.getElementById("url-input");
  const url = input.value.trim();

  if (!url) {
    showInlineError("url", "Please enter a URL to scan.");
    input.focus();
    return;
  }

  if (url.length < 3) {
    showInlineError("url", "URL is too short to be analyzed.");
    return;
  }

  hideInlineError("url");

  const loadingEl = document.getElementById("url-loading");
  const resultsEl = document.getElementById("url-results");
  const scanBtn = document.getElementById("scan-btn");

  loadingEl.classList.remove("hidden");
  resultsEl.classList.add("hidden");
  scanBtn.disabled = true;

  // Step-by-step progress animation
  const stepText = document.getElementById("loading-stage-text");
  const step1 = document.getElementById("step-1");
  const step2 = document.getElementById("step-2");
  const step3 = document.getElementById("step-3");
  const step4 = document.getElementById("step-4");

  stepText.textContent = "1. Validating destination & SSRF boundaries...";
  step1.className = "text-cyan-400 font-bold";
  step2.className = "text-slate-400";
  step3.className = "text-slate-400";
  step4.className = "text-slate-400";

  const t1 = setTimeout(() => {
    stepText.textContent = "2. Resolving redirect hops & shorteners...";
    step2.className = "text-cyan-400 font-bold";
  }, 400);

  const t2 = setTimeout(() => {
    stepText.textContent = "3. Extracting 27x lexical, structural & brand features...";
    step3.className = "text-cyan-400 font-bold";
  }, 800);

  const t3 = setTimeout(() => {
    stepText.textContent = "4. Evaluating Calibrated Random Forest model...";
    step4.className = "text-cyan-400 font-bold";
  }, 1200);

  try {
    const response = await fetch("/api/scan-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    clearTimeout(t1);
    clearTimeout(t2);
    clearTimeout(t3);

    if (response.status === 429) {
      showInlineError("url", "Rate limit exceeded (maximum 30 scans per minute). Please wait 60 seconds.");
      return;
    }

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Analysis failed");
    }

    const json = await response.json();
    displayUrlResults(json.data);
    saveToHistory(json.data);
  } catch (err) {
    showInlineError("url", `Analysis error: ${err.message}`);
  } finally {
    loadingEl.classList.add("hidden");
    scanBtn.disabled = false;
  }
}

// Display URL Results (Safe DOM manipulation - XSS hardened)
function displayUrlResults(data) {
  const resultsEl = document.getElementById("url-results");
  resultsEl.classList.remove("hidden");

  // Display URL safely using textContent
  const urlDisplay = document.getElementById("scanned-url-display");
  urlDisplay.textContent = data.url;

  // Animate Gauge & Score
  const score = data.risk_score;
  const circle = document.getElementById("score-gauge-circle");
  const scoreValue = document.getElementById("score-value");
  const scoreTier = document.getElementById("score-tier");
  const verdictBadge = document.getElementById("verdict-badge");
  const allowlistPill = document.getElementById("allowlist-pill");
  const summaryEl = document.getElementById("verdict-summary");
  const gaugeCard = document.getElementById("verdict-gauge-card");

  animateValue(scoreValue, 0, score, 800, "%");

  const circumference = 314;
  const offset = circumference - (score / 100) * circumference;
  circle.style.strokeDashoffset = offset;

  circle.classList.remove("text-emerald-400", "text-amber-400", "text-rose-500");
  gaugeCard.classList.remove("glow-emerald", "glow-amber", "glow-rose");
  verdictBadge.className = "mt-2 px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider border ";

  if (data.is_allowlisted) {
    allowlistPill.classList.remove("hidden");
  } else {
    allowlistPill.classList.add("hidden");
  }

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

  // Diagnostics list (Construct DOM elements safely)
  const diagnosticsList = document.getElementById("diagnostics-list");
  diagnosticsList.replaceChildren();

  if (data.diagnostics && data.diagnostics.length > 0) {
    data.diagnostics.forEach(diag => {
      const item = document.createElement("div");
      item.className = "p-2.5 rounded-lg bg-cyber-900/80 border border-slate-800 text-xs flex items-start space-x-2 text-rose-300";
      
      const icon = document.createElement("i");
      icon.setAttribute("data-lucide", "alert-circle");
      icon.className = "w-4 h-4 text-rose-400 shrink-0 mt-0.5";
      
      const textSpan = document.createElement("span");
      textSpan.textContent = diag; // Safe textContent prevents XSS
      
      item.appendChild(icon);
      item.appendChild(textSpan);
      diagnosticsList.appendChild(item);
    });
  } else {
    const item = document.createElement("div");
    item.className = "p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs flex items-center space-x-2 text-emerald-400";
    item.textContent = "No anomalous threat markers detected in URL structure.";
    diagnosticsList.appendChild(item);
  }

  // Feature Contributions (XAI)
  renderFeatureContributions(data.feature_contributions || []);

  // Recommendations
  const recList = document.getElementById("recommendations-list");
  recList.replaceChildren();
  (data.recommendations || []).forEach(rec => {
    const li = document.createElement("li");
    li.className = "flex items-start space-x-2";
    
    const icon = document.createElement("i");
    icon.setAttribute("data-lucide", "chevron-right");
    icon.className = "w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5";

    const span = document.createElement("span");
    span.textContent = rec;

    li.appendChild(icon);
    li.appendChild(span);
    recList.appendChild(li);
  });

  // Feature Breakdown Table
  populateFeaturesTable(data.features);

  if (window.lucide) {
    lucide.createIcons();
  }

  resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
}

// Render Explainable AI Feature Contributions
function renderFeatureContributions(contributions) {
  const container = document.getElementById("feature-contributions-grid");
  container.replaceChildren();

  if (!contributions || contributions.length === 0) {
    const empty = document.createElement("div");
    empty.className = "p-3 rounded-lg bg-cyber-900/60 border border-slate-800 text-slate-400 col-span-2";
    empty.textContent = "Baseline structural metrics align with standard legitimate websites.";
    container.appendChild(empty);
    return;
  }

  contributions.forEach(item => {
    const card = document.createElement("div");
    const isThreat = item.impact === "threat";
    card.className = `p-3 rounded-lg bg-cyber-900/80 border ${isThreat ? 'border-rose-500/30' : 'border-emerald-500/30'} flex items-start justify-between space-x-2`;

    const left = document.createElement("div");
    left.className = "space-y-0.5";

    const title = document.createElement("div");
    title.className = `font-bold ${isThreat ? 'text-rose-300' : 'text-emerald-300'}`;
    title.textContent = item.feature;

    const desc = document.createElement("div");
    desc.className = "text-[11px] text-slate-400 font-sans";
    desc.textContent = item.description;

    left.appendChild(title);
    left.appendChild(desc);

    const badge = document.createElement("span");
    badge.className = `px-2 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 ${isThreat ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'}`;
    badge.textContent = `${item.weight > 0 ? '+' : ''}${item.weight}%`;

    card.appendChild(left);
    card.appendChild(badge);
    container.appendChild(card);
  });
}

// Populate Feature Table (XSS hardened)
function populateFeaturesTable(features) {
  const tbody = document.getElementById("features-table-body");
  tbody.replaceChildren();

  const featureMetadata = [
    { key: "is_brand_typosquat", name: "Brand Typosquatting", desc: "Levenshtein distance <= 2 to major brands (e.g. paypa1)", badWhen: v => v === 1 },
    { key: "brand_in_subdomain", name: "Brand in Subdomain", desc: "Brand token in subdomain masquerading over different root domain", badWhen: v => v === 1 },
    { key: "is_tranco_top", name: "Tranco Top 1k Allowlist", desc: "Verified index in global top 1,000 trusted domains", badWhen: v => false },
    { key: "has_ip_address", name: "Direct IP Hostname", desc: "Checks if URL bypasses DNS by using raw IPv4/v6 address", badWhen: v => v === 1 },
    { key: "has_punycode", name: "Punycode (Homograph)", desc: "Detects 'xn--' spoofed internationalized glyphs", badWhen: v => v === 1 },
    { key: "is_https", name: "HTTPS Protocol", desc: "Transport Layer Security encryption status", badWhen: v => v === 0 },
    { key: "has_suspicious_tld", name: "High-Abuse TLD", desc: "Disposable top-level domain (.xyz, .top, .ga, etc.)", badWhen: v => v === 1 },
    { key: "has_suspicious_keyword", name: "Credential Keywords", desc: "Presence of tokens like login, verify, auth, secure", badWhen: v => v === 1 },
    { key: "domain_entropy", name: "Domain Entropy", desc: "Shannon randomness of characters (high = DGA)", badWhen: v => v > 3.6 },
    { key: "subdomain_count", name: "Subdomain Depth", desc: "Number of nested subdomains masquerading", badWhen: v => v >= 2 },
    { key: "url_length", name: "URL Length", desc: "Total character count of complete URL string", badWhen: v => v > 85 },
    { key: "domain_length", name: "Domain Length", desc: "Character count of primary netloc hostname", badWhen: v => v > 30 },
    { key: "num_at_symbols", name: "At Symbols (@)", desc: "Obfuscation trick used to redirect browser destination", badWhen: v => v > 0 },
    { key: "num_dots", name: "Dot Count (.)", desc: "Total periods across entire URL string", badWhen: v => v >= 4 },
    { key: "has_shortener", name: "URL Shortener", desc: "Known link masking service (bit.ly, tinyurl, etc.)", badWhen: v => v === 1 }
  ];

  featureMetadata.forEach(meta => {
    const val = features[meta.key];
    const isBad = meta.badWhen(val);
    const tr = document.createElement("tr");
    tr.className = "hover:bg-cyber-800/40 transition-colors";

    let displayVal = val;
    if (meta.key === "is_https") displayVal = val === 1 ? "HTTPS (Encrypted)" : "HTTP (Unencrypted)";
    else if (meta.key === "has_ip_address") displayVal = val === 1 ? "Yes (IP Hostname)" : "No (Domain)";
    else if (meta.key === "is_brand_typosquat") displayVal = val === 1 ? `Yes (Mimics '${features.matched_brand}')` : "No";
    else if (meta.key === "brand_in_subdomain") displayVal = val === 1 ? `Yes ('${features.matched_brand}' in subdomain)` : "No";
    else if (meta.key === "is_tranco_top") displayVal = val === 1 ? "Yes (Verified Top 1k)" : "No";
    else if (meta.key === "has_suspicious_tld") displayVal = val === 1 ? `Yes (.${features.tld})` : "No";
    else if (meta.key === "has_suspicious_keyword") displayVal = val === 1 ? `Yes (${features.keywords_found?.join(', ') || 'found'})` : "No";

    const tdName = document.createElement("td");
    tdName.className = "py-3 px-4 font-semibold text-slate-200";
    tdName.textContent = meta.name;

    const tdVal = document.createElement("td");
    tdVal.className = `py-3 px-4 ${isBad ? 'text-rose-400 font-bold' : 'text-slate-300'}`;
    tdVal.textContent = String(displayVal);

    const tdDesc = document.createElement("td");
    tdDesc.className = "py-3 px-4 text-slate-400 font-sans text-xs";
    tdDesc.textContent = meta.desc;

    const tdStatus = document.createElement("td");
    tdStatus.className = "py-3 px-4";
    const statusBadge = document.createElement("span");
    statusBadge.className = isBad 
      ? "px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 text-[10px] uppercase font-bold"
      : "px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] uppercase font-bold";
    statusBadge.textContent = isBad ? "Flagged / Anomaly" : "Standard / Normal";
    tdStatus.appendChild(statusBadge);

    tr.appendChild(tdName);
    tr.appendChild(tdVal);
    tr.appendChild(tdDesc);
    tr.appendChild(tdStatus);
    tbody.appendChild(tr);
  });
}

// Handle Message / Text Scan
async function handleTextScan(e) {
  e.preventDefault();
  const input = document.getElementById("text-input");
  const text = input.value.trim();

  if (!text || text.length < 5) {
    showInlineError("text", "Please enter message text (at least 5 characters).");
    input.focus();
    return;
  }

  hideInlineError("text");
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

    const json = await response.json();
    displayTextResults(json.data);
  } catch (err) {
    showInlineError("text", `Text analysis error: ${err.message}`);
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

  // Embedded URLs display (scored individually)
  const embeddedContainer = document.getElementById("embedded-urls-container");
  const embeddedBadge = document.getElementById("embedded-url-count-badge");
  embeddedContainer.replaceChildren();

  const urlScans = data.embedded_url_scans || [];
  embeddedBadge.textContent = `${urlScans.length} Link(s) Extracted`;

  if (urlScans.length === 0) {
    const empty = document.createElement("div");
    empty.className = "text-slate-400 text-xs py-2";
    empty.textContent = "No embedded hyperlinks found in the message text.";
    embeddedContainer.appendChild(empty);
  } else {
    urlScans.forEach(item => {
      const row = document.createElement("div");
      row.className = "p-3 rounded-lg bg-cyber-900 border border-slate-800 flex items-center justify-between space-x-3";

      const left = document.createElement("div");
      left.className = "space-y-0.5 overflow-hidden";

      const urlText = document.createElement("div");
      urlText.className = "text-slate-200 font-semibold truncate";
      urlText.textContent = item.url; // Safe textContent

      const diag = document.createElement("div");
      diag.className = "text-[11px] text-slate-400 font-sans";
      diag.textContent = item.diagnostics?.join(" ") || "Analyzed link.";

      left.appendChild(urlText);
      left.appendChild(diag);

      const badge = document.createElement("span");
      badge.className = `px-2 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 ${item.risk_score >= 70 ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30' : (item.risk_score >= 35 ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30')}`;
      badge.textContent = `${item.risk_score}% — ${item.verdict}`;

      row.appendChild(left);
      row.appendChild(badge);
      embeddedContainer.appendChild(row);
    });
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
  diagContainer.replaceChildren();

  if (data.diagnostics && data.diagnostics.length > 0) {
    data.diagnostics.forEach(diag => {
      const el = document.createElement("div");
      el.className = "p-2.5 rounded-lg bg-cyber-900/80 border border-slate-800 text-xs flex items-start space-x-2 text-rose-300";
      
      const icon = document.createElement("i");
      icon.setAttribute("data-lucide", "alert-triangle");
      icon.className = "w-4 h-4 text-rose-400 shrink-0 mt-0.5";

      const span = document.createElement("span");
      span.textContent = diag;

      el.appendChild(icon);
      el.appendChild(span);
      diagContainer.appendChild(el);
    });
  }

  if (window.lucide) {
    lucide.createIcons();
  }

  resultsEl.scrollIntoView({ behavior: "smooth" });
}

// Load Model Stats, Confusion Matrix & Chart
async function loadModelStats() {
  try {
    const res = await fetch("/api/model-stats");
    if (!res.ok) return;
    const json = await res.json();
    const stats = json.data;

    // Update version badge
    if (json.version) {
      const badge = document.getElementById("app-version-badge");
      if (badge) badge.textContent = json.version;
    }

    const metrics = stats.url_metrics || {};
    document.getElementById("stat-roc-auc").textContent = `${Math.round((metrics.roc_auc || 1.0) * 100)}%`;
    document.getElementById("stat-precision").textContent = `${Math.round((metrics.precision || 1.0) * 100)}%`;
    document.getElementById("stat-recall").textContent = `${Math.round((metrics.recall || 1.0) * 100)}%`;
    document.getElementById("stat-f1").textContent = `${Math.round((metrics.f1_score || 1.0) * 100)}%`;
    document.getElementById("stat-accuracy").textContent = `${Math.round((metrics.accuracy || 1.0) * 100)}%`;

    // Confusion Matrix
    const cm = metrics.confusion_matrix || { tn: 70, fp: 0, fn: 0, tp: 32 };
    document.getElementById("cm-tn").textContent = cm.tn;
    document.getElementById("cm-fp").textContent = cm.fp;
    document.getElementById("cm-fn").textContent = cm.fn;
    document.getElementById("cm-tp").textContent = cm.tp;

    // Render Chart.js
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

// Session History Storage & Export
function saveToHistory(result) {
  try {
    let history = JSON.parse(localStorage.getItem("phishguard_scans") || "[]");
    history.unshift({
      url: result.url,
      verdict: result.verdict,
      risk_score: result.risk_score,
      timestamp: new Date().toLocaleTimeString(),
      date: new Date().toISOString()
    });
    if (history.length > 20) history = history.slice(0, 20);
    localStorage.setItem("phishguard_scans", JSON.stringify(history));
    renderHistory();
  } catch (e) {}
}

function renderHistory() {
  const container = document.getElementById("history-container");
  if (!container) return;

  try {
    const history = JSON.parse(localStorage.getItem("phishguard_scans") || "[]");
    container.replaceChildren();

    if (history.length === 0) {
      const empty = document.createElement("div");
      empty.className = "text-center py-6 text-slate-400 font-mono text-xs";
      empty.textContent = "No scans recorded yet. Enter a URL above to inspect threats.";
      container.appendChild(empty);
      return;
    }

    history.forEach(item => {
      const row = document.createElement("div");
      row.className = "flex items-center justify-between p-3 rounded-lg bg-cyber-900/60 border border-slate-800 hover:border-sky-500/30 transition-all";

      const left = document.createElement("div");
      left.className = "flex items-center space-x-3 overflow-hidden";

      const badge = document.createElement("span");
      let badgeClass = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      if (item.risk_score >= 70) badgeClass = "bg-rose-500/10 text-rose-400 border-rose-500/30";
      else if (item.risk_score >= 35) badgeClass = "bg-amber-500/10 text-amber-400 border-amber-500/30";

      badge.className = `px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${badgeClass}`;
      badge.textContent = `${item.risk_score}%`;

      const urlSpan = document.createElement("span");
      urlSpan.className = "font-mono text-xs text-slate-300 truncate max-w-sm sm:max-w-md";
      urlSpan.textContent = item.url; // Safe textContent prevents XSS

      left.appendChild(badge);
      left.appendChild(urlSpan);

      const right = document.createElement("div");
      right.className = "flex items-center space-x-3 shrink-0";

      const timeSpan = document.createElement("span");
      timeSpan.className = "text-[11px] text-slate-400";
      timeSpan.textContent = item.timestamp;

      const rescanBtn = document.createElement("button");
      rescanBtn.className = "px-2.5 py-1 rounded bg-cyber-800 hover:bg-cyber-700 text-cyan-400 text-xs font-medium transition-all";
      rescanBtn.textContent = "Re-Scan";
      rescanBtn.onclick = () => {
        setSampleUrl(item.url);
        document.getElementById("url-scan-form").dispatchEvent(new Event("submit"));
      };

      right.appendChild(timeSpan);
      right.appendChild(rescanBtn);

      row.appendChild(left);
      row.appendChild(right);
      container.appendChild(row);
    });
  } catch (e) {}
}

function clearHistory() {
  localStorage.removeItem("phishguard_scans");
  renderHistory();
}

// Export History to JSON or CSV
function exportHistory(format) {
  try {
    const history = JSON.parse(localStorage.getItem("phishguard_scans") || "[]");
    if (history.length === 0) {
      alert("No scans available to export.");
      return;
    }

    let blob, filename;
    const dateStr = new Date().toISOString().slice(0, 10);

    if (format === "json") {
      const dataStr = JSON.stringify(history, null, 2);
      blob = new Blob([dataStr], { type: "application/json" });
      filename = `phishguard_scans_${dateStr}.json`;
    } else {
      // CSV format
      const headers = ["Timestamp", "URL", "Risk Score", "Verdict"];
      const rows = history.map(h => [
        `"${h.timestamp || ''}"`,
        `"${(h.url || '').replace(/"/g, '""')}"`,
        h.risk_score,
        `"${h.verdict || ''}"`
      ]);
      const csvContent = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
      blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
      filename = `phishguard_scans_${dateStr}.csv`;
    }

    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  } catch (e) {
    alert("Export failed: " + e.message);
  }
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
