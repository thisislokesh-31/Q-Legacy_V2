// Q-Legacy Frontend Logic

let currentAnalysisResult = null;
let currentAesSession = null;
const API_KEY = window.QLEGACY_API_KEY || "";

function buildHeaders(extra = {}) {
  const headers = { ...extra };
  if (API_KEY) {
    headers["X-API-Key"] = API_KEY;
  }
  return headers;
}

document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  setupDragAndDrop();
  checkHealth();
  loadDashboard();
  loadInventory();
});

// ----------------------------------------------------
// Navigation / Tab Switching
// ----------------------------------------------------
function setupTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const targetId = tab.getAttribute("data-tab");
      switchTab(targetId);
    });
  });
}

function switchTab(targetId) {
  document.querySelectorAll(".nav-tab").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

  const targetTabBtn = document.querySelector(`[data-tab="${targetId}"]`);
  const targetContent = document.getElementById(targetId);

  if (targetTabBtn) targetTabBtn.classList.add("active");
  if (targetContent) targetContent.classList.add("active");

  if (targetId === "dashboard-tab") loadDashboard();
  if (targetId === "inventory-tab") loadInventory();
}

// ----------------------------------------------------
// Health Check
// ----------------------------------------------------
async function checkHealth() {
  try {
    const res = await fetch("/health");
    if (res.ok) {
      document.getElementById("backend-status-text").textContent = "Engine Online";
    } else {
      document.getElementById("backend-status-text").textContent = "Degraded";
    }
  } catch (err) {
    document.getElementById("backend-status-text").textContent = "Offline";
  }
}

// ----------------------------------------------------
// Dashboard Metrics
// ----------------------------------------------------
async function loadDashboard() {
  try {
    const res = await fetch("/api/dashboard", {
      headers: buildHeaders(),
    });
    if (!res.ok) throw new Error("Failed to load dashboard data");
    const data = await res.json();

    document.getElementById("stat-total-assets").textContent = data.total_assets;
    document.getElementById("stat-vulnerable").textContent = data.quantum_vulnerable_count;
    document.getElementById("stat-pqc").textContent = data.quantum_safe_count;
    document.getElementById("stat-readiness").textContent = `${data.quantum_readiness_percentage}%`;

    const summaryEl = document.getElementById("migration-summary-text");
    if (data.migration_summary) {
      summaryEl.innerHTML = `<strong>Status:</strong> ${data.migration_summary.recommended_next_step}`;
    }
  } catch (err) {
    console.error("Dashboard error:", err);
  }
}

// ----------------------------------------------------
// Asset Scanner & Upload
// ----------------------------------------------------
function setupDragAndDrop() {
  const dropZone = document.getElementById("drop-zone");
  if (!dropZone) return;

  ["dragenter", "dragover"].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.add("dragover");
    }, false);
  });

  ["dragleave", "drop"].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.remove("dragover");
    }, false);
  });

  dropZone.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
      analyzeFile(files[0]);
    }
  });
}

function handleFileUpload(event) {
  const file = event.target.files[0];
  if (file) {
    analyzeFile(file);
  }
}

async function analyzeFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  try {
    document.getElementById("drop-zone").style.opacity = "0.5";
    const res = await fetch("/api/analyze", {
      method: "POST",
      body: formData,
      headers: buildHeaders(),
    });

    if (!res.ok) {
      const err = await res.json();
      alert(`Analysis Failed: ${err.detail || "Server error"}`);
      return;
    }

    const data = await res.json();
    currentAnalysisResult = data;
    renderAnalysisResult(data);
  } catch (err) {
    alert(`Upload failed: ${err.message}`);
  } finally {
    document.getElementById("drop-zone").style.opacity = "1";
  }
}

function renderAnalysisResult(data) {
  document.getElementById("drop-zone").style.display = "none";
  document.getElementById("analysis-container").style.display = "block";

  document.getElementById("result-filename").textContent = data.filename;
  document.getElementById("result-asset-type").textContent = data.asset_type;

  const badge = document.getElementById("result-risk-badge");
  badge.className = `risk-badge risk-${data.overall_risk_level}`;
  badge.textContent = `${data.overall_risk_level} RISK`;

  document.getElementById("result-meta").textContent = 
    `Confidence: ${data.overall_confidence} | Priority: ${data.overall_priority}`;

  document.getElementById("result-algorithms").textContent = 
    data.algorithms_detected.length > 0 ? data.algorithms_detected.join(", ") : "None Detected";

  document.getElementById("result-recommendation").textContent = data.overall_recommendation;
  document.getElementById("result-details").textContent = JSON.stringify(data.findings, null, 2);
}

function resetScanner() {
  currentAnalysisResult = null;
  document.getElementById("file-input").value = "";
  document.getElementById("analysis-container").style.display = "none";
  document.getElementById("drop-zone").style.display = "block";
}

async function saveScanToInventory() {
  if (!currentAnalysisResult) return;

  const payload = {
    filename: currentAnalysisResult.filename,
    asset_type: currentAnalysisResult.asset_type,
    algorithms: currentAnalysisResult.algorithms_detected,
    risk_level: currentAnalysisResult.overall_risk_level,
    recommendation: currentAnalysisResult.overall_recommendation,
    confidence: currentAnalysisResult.overall_confidence,
    priority: currentAnalysisResult.overall_priority,
    manual_review_required: Boolean(currentAnalysisResult.manual_review_required),
    evidence: Array.isArray(currentAnalysisResult.evidence) ? currentAnalysisResult.evidence : [],
    details: currentAnalysisResult.details,
  };

  try {
    const res = await fetch("/api/assets", {
      method: "POST",
      headers: buildHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(payload),
    });

    if (!res.ok) throw new Error("Failed to register asset in inventory");

    alert("Asset successfully registered into inventory!");
    switchTab("inventory-tab");
  } catch (err) {
    alert(`Error: ${err.message}`);
  }
}

// ----------------------------------------------------
// Inventory Management
// ----------------------------------------------------
async function loadInventory() {
  const tbody = document.getElementById("inventory-tbody");
  tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">Loading inventory assets...</td></tr>`;

  try {
    const res = await fetch("/api/assets", {
      headers: buildHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch assets");
    const assets = await res.json();

    if (assets.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No assets in inventory yet. Use the scanner to add assets.</td></tr>`;
      return;
    }

    tbody.innerHTML = assets.map(a => `
      <tr>
        <td>#${a.id}</td>
        <td><strong>${escapeHtml(a.filename)}</strong></td>
        <td>${escapeHtml(a.asset_type)}</td>
        <td><span style="color: var(--accent-cyan); font-weight: 600;">${a.algorithms.join(", ") || "None"}</span></td>
        <td><span class="risk-badge risk-${a.risk_level}">${a.risk_level}</span></td>
        <td><span style="font-weight: 600;">${a.priority}</span></td>
        <td style="max-width: 260px; font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(a.recommendation)}</td>
        <td>
          <button class="btn btn-danger" onclick="deleteAsset(${a.id})">Delete</button>
        </td>
      </tr>
    `).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--accent-rose);">Error: ${err.message}</td></tr>`;
  }
}

async function deleteAsset(id) {
  if (!confirm(`Are you sure you want to delete asset #${id}?`)) return;

  try {
    const res = await fetch(`/api/assets/${id}`, {
      method: "DELETE",
      headers: buildHeaders(),
    });
    if (!res.ok) throw new Error("Failed to delete asset");
    loadInventory();
  } catch (err) {
    alert(`Delete failed: ${err.message}`);
  }
}

// ----------------------------------------------------
// AES-256-GCM Cryptography Lab
// ----------------------------------------------------
async function executeAesEncrypt() {
  const plaintext = document.getElementById("aes-plaintext-input").value;
  if (!plaintext) {
    alert("Please enter text to encrypt.");
    return;
  }

  try {
    const res = await fetch("/api/crypto/aes/encrypt", {
      method: "POST",
      headers: buildHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ plaintext }),
    });

    if (!res.ok) throw new Error("Encryption failed");
    const data = await res.json();
    currentAesSession = data;

    document.getElementById("aes-ciphertext-out").textContent = data.ciphertext_hex;
    document.getElementById("aes-keynonce-out").textContent = 
      `KEY (256-bit): ${data.key_hex}\nNONCE (96-bit): ${data.nonce_hex}`;

    const resBox = document.getElementById("aes-decrypt-result");
    resBox.style.display = "none";
  } catch (err) {
    alert(`Error: ${err.message}`);
  }
}

async function executeAesDecrypt(simulateTamper) {
  if (!currentAesSession) {
    alert("Please encrypt a message first!");
    return;
  }

  let ciphertextHex = currentAesSession.ciphertext_hex;
  if (simulateTamper) {
    // Flip leading hex chars
    const char = ciphertextHex[0] === 'a' ? 'b' : 'a';
    ciphertextHex = char + ciphertextHex.substring(1);
  }

  const payload = {
    key_hex: currentAesSession.key_hex,
    nonce_hex: currentAesSession.nonce_hex,
    ciphertext_hex: ciphertextHex,
  };

  const resBox = document.getElementById("aes-decrypt-result");
  resBox.style.display = "block";

  try {
    const res = await fetch("/api/crypto/aes/decrypt", {
      method: "POST",
      headers: buildHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    if (res.ok) {
      resBox.className = "info-note";
      resBox.style.borderLeftColor = "var(--accent-emerald)";
      resBox.innerHTML = `<strong>Decryption Successful:</strong> "${escapeHtml(data.plaintext)}"<br><span style="color: var(--accent-emerald);">Authentication Tag Verified.</span>`;
    } else {
      resBox.className = "info-note";
      resBox.style.borderLeftColor = "var(--accent-rose)";
      resBox.innerHTML = `<strong>Cryptographic Rejection:</strong> ${data.detail || "Tamper detected!"}`;
    }
  } catch (err) {
    resBox.innerHTML = `<strong>Error:</strong> ${err.message}`;
  }
}

// ----------------------------------------------------
// ML-KEM-768 (NIST FIPS 203) Lab
// ----------------------------------------------------
async function executeMlkemFullDemo() {
  try {
    const noteEl = document.getElementById("mlkem-status-note");
    noteEl.textContent = "Executing NIST FIPS 203 Keypair Generation, Encapsulation & Decapsulation...";

    const res = await fetch("/api/crypto/mlkem/demo", {
      headers: buildHeaders(),
    });
    if (!res.ok) throw new Error("ML-KEM demo failed");
    const data = await res.json();

    document.getElementById("mlkem-pk-out").textContent = data.simulation.recipient_public_key_hex_truncated;
    document.getElementById("mlkem-ct-out").textContent = data.simulation.ciphertext_hex_truncated;

    document.getElementById("mlkem-secrets-out").textContent = 
      `Sender Secret:    ${data.simulation.sender_derived_shared_secret_hex}\nRecipient Secret: ${data.simulation.recipient_derived_shared_secret_hex}\nMatch Verified:   ${data.simulation.shared_secrets_identical}`;

    noteEl.innerHTML = `<strong>Handshake Verified:</strong> Recipient and Sender independently derived identical 256-bit symmetric shared secrets over untrusted channel.`;
  } catch (err) {
    alert(`ML-KEM Error: ${err.message}`);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
