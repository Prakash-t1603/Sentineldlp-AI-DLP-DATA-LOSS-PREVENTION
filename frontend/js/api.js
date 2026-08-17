const API_BASE = "/api/v1";

const API = {
  getToken() {
    return localStorage.getItem("sentinel_token") || "";
  },

  getUser() {
    try {
      return JSON.parse(localStorage.getItem("sentinel_user") || "{}");
    } catch {
      return {};
    }
  },

  setAuth(token, user) {
    localStorage.setItem("sentinel_token", token);
    localStorage.setItem("sentinel_user", JSON.stringify(user));
  },

  clearAuth() {
    localStorage.removeItem("sentinel_token");
    localStorage.removeItem("sentinel_user");
  },

  async request(endpoint, options = {}) {
    const headers = options.headers || {};
    const token = this.getToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }

    options.headers = headers;

    try {
      const resp = await fetch(`${API_BASE}${endpoint}`, options);

      if (resp.status === 401) {
        // Unauthorized
        this.clearAuth();
        if (!window.location.pathname.includes("login")) {
          window.location.href = "/login";
        }
        throw new Error("Session expired. Please log in again.");
      }

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({ detail: "An error occurred" }));
        throw new Error(errData.detail || `HTTP Error ${resp.status}`);
      }

      const contentType = resp.headers.get("content-type");
      if (contentType && contentType.includes("text/csv")) {
        return await resp.text();
      }

      if (resp.status === 204) {
        return null;
      }

      return await resp.json();
    } catch (err) {
      console.error(`API Error on ${endpoint}:`, err);
      throw err;
    }
  },

  get(endpoint) {
    return this.request(endpoint, { method: "GET" });
  },

  post(endpoint, body) {
    return this.request(endpoint, {
      method: "POST",
      body: body instanceof FormData ? body : JSON.stringify(body)
    });
  },

  patch(endpoint, body) {
    return this.request(endpoint, {
      method: "PATCH",
      body: JSON.stringify(body)
    });
  },

  delete(endpoint) {
    return this.request(endpoint, { method: "DELETE" });
  }
};

// UI Utilities & Formatters
function showToast(message, type = "info") {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = "toast-msg";
  
  let icon = "fa-info-circle text-info";
  if (type === "success") icon = "fa-check-circle text-success";
  if (type === "warning") icon = "fa-exclamation-triangle text-warning";
  if (type === "error") icon = "fa-radiation text-danger";

  toast.innerHTML = `
    <i class="fas ${icon} fa-lg"></i>
    <div class="flex-grow-1 text-white">${message}</div>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(100%)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function formatRiskBadge(score) {
  const numScore = (typeof score === 'number' && !isNaN(score)) ? (score % 1 === 0 ? score : score.toFixed(1)) : score;
  let level = "LOW";
  let cls = "badge-risk-low";
  if (numScore >= 80) { level = "CRITICAL"; cls = "badge-risk-critical"; }
  else if (numScore >= 60) { level = "HIGH"; cls = "badge-risk-high"; }
  else if (numScore >= 30) { level = "MEDIUM"; cls = "badge-risk-medium"; }

  return `<span class="badge-risk ${cls}">${numScore} · ${level}</span>`;
}

function formatSeverityBadge(severity) {
  const sev = (severity || "LOW").toUpperCase();
  let cls = "badge-risk-low";
  if (sev === "CRITICAL") cls = "badge-risk-critical";
  else if (sev === "HIGH") cls = "badge-risk-high";
  else if (sev === "MEDIUM") cls = "badge-risk-medium";

  return `<span class="badge-risk ${cls}">${sev}</span>`;
}

function formatClassificationTag(classification) {
  const c = (classification || "PUBLIC").toUpperCase();
  let cls = "tag-public";
  if (c === "HIGHLY_CONFIDENTIAL") cls = "tag-highly-confidential";
  else if (c === "CONFIDENTIAL") cls = "tag-confidential";
  else if (c === "INTERNAL") cls = "tag-internal";

  return `<span class="tag-class ${cls}">${c.replace("_", " ")}</span>`;
}

function formatStatusDot(status) {
  const s = (status || "ONLINE").toUpperCase();
  let cls = "online";
  if (s === "OFFLINE") cls = "offline";
  if (s === "SUSPICIOUS") cls = "suspicious";

  return `<span class="status-dot ${cls}"></span> <span class="ms-1">${s}</span>`;
}

function formatDate(isoStr) {
  if (!isoStr) return "N/A";
  const d = new Date(isoStr);
  return d.toLocaleString("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit"
  });
}

function formatAlertTypeBadge(alertType) {
  const type = alertType || "UNKNOWN";
  if (type.includes("MESSAGING") || type.includes("WHATSAPP")) {
    return `<span class="badge bg-success bg-opacity-25 text-success border border-success"><i class="fa-brands fa-whatsapp me-1"></i> WhatsApp / Chat</span>`;
  }
  if (type.includes("WEB_STORAGE") || type.includes("CLOUD")) {
    return `<span class="badge bg-primary bg-opacity-25 text-info border border-primary"><i class="fas fa-cloud-arrow-up me-1"></i> Web Storage</span>`;
  }
  if (type.includes("EMAIL")) {
    return `<span class="badge bg-info bg-opacity-25 text-info border border-info"><i class="fas fa-envelope me-1"></i> Email</span>`;
  }
  if (type.includes("USB")) {
    return `<span class="badge bg-danger bg-opacity-25 text-danger border border-danger"><i class="fas fa-usb me-1"></i> USB Drive</span>`;
  }
  if (type.includes("CLIPBOARD")) {
    return `<span class="badge bg-warning bg-opacity-25 text-warning border border-warning"><i class="fas fa-clipboard me-1"></i> Clipboard</span>`;
  }
  return `<span class="badge bg-secondary bg-opacity-25 text-white border border-secondary">${type.replace(/_/g, ' ')}</span>`;
}

function formatAlertStatusBadge(status) {
  const s = (status || "OPEN").toUpperCase();
  if (s === "RESOLVED" || s === "COMPLETED") {
    return `<span class="badge bg-success bg-opacity-25 text-success border border-success"><i class="fas fa-circle-check me-1"></i> Completed / Resolved</span>`;
  }
  if (s === "INVESTIGATING" || s === "ACKNOWLEDGED") {
    return `<span class="badge bg-info bg-opacity-25 text-info border border-info"><i class="fas fa-magnifying-glass me-1"></i> Under Investigation</span>`;
  }
  if (s === "FALSE_POSITIVE") {
    return `<span class="badge border" style="background: rgba(139, 92, 246, 0.2); border-color: rgba(139, 92, 246, 0.4); color: #c4b5fd;"><i class="fas fa-ban me-1"></i> False Positive</span>`;
  }
  return `<span class="badge bg-warning bg-opacity-25 text-warning border border-warning"><i class="fas fa-triangle-exclamation me-1"></i> Open</span>`;
}

function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function exportAlertsCSV() {
  try {
    const csvData = await API.get("/reports/export/alerts.csv");
    downloadFile(csvData, "sentineldlp_alerts_export.csv", "text/csv");
    if (typeof showToast === "function") {
      showToast("Alerts CSV exported successfully", "success");
    }
  } catch (err) {
    if (typeof showToast === "function") {
      showToast("Export failed: " + err.message, "error");
    } else {
      alert("Export failed: " + err.message);
    }
  }
}

async function exportActivitiesCSV() {
  try {
    const csvData = await API.get("/reports/export/activities.csv");
    downloadFile(csvData, "sentineldlp_activities_export.csv", "text/csv");
    if (typeof showToast === "function") {
      showToast("Activities CSV exported successfully", "success");
    }
  } catch (err) {
    if (typeof showToast === "function") {
      showToast("Export failed: " + err.message, "error");
    } else {
      alert("Export failed: " + err.message);
    }
  }
}


