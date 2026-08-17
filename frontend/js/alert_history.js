// Alert History & Lifecycle Management Controller
let allAlertHistory = [];
let activeStatusFilter = "";

document.addEventListener("DOMContentLoaded", () => {
  // Read any initial status filter from URL query param if present (e.g. /alert-history?status=OPEN)
  const urlParams = new URLSearchParams(window.location.search);
  const statusParam = urlParams.get("status");
  if (statusParam) {
    activeStatusFilter = statusParam.toUpperCase();
    updateTabVisuals(activeStatusFilter);
  }

  loadAlertHistory();

  // Auto-refresh every 3 seconds for real-time live telemetry
  setInterval(loadAlertHistory, 3000);

  // Setup event listeners
  document.getElementById("hist-filter-severity")?.addEventListener("change", applyFilters);
  document.getElementById("hist-filter-source")?.addEventListener("change", applyFilters);
  document.getElementById("hist-filter-search")?.addEventListener("input", applyFilters);
});

async function loadAlertHistory() {
  try {
    const [alertsData, statsData] = await Promise.all([
      API.get("/alerts"),
      API.get("/alerts/stats").catch(() => null)
    ]);

    allAlertHistory = alertsData || [];

    // Render Stats
    renderStats(statsData, allAlertHistory);

    // Apply active filters and render table
    applyFilters();
  } catch (err) {
    console.debug("Alert history polling:", err.message);
  }
}

function renderStats(stats, alerts) {
  let total = alerts.length;
  let openCount = 0;
  let investigatingCount = 0;
  let resolvedCount = 0;
  let falsePosCount = 0;

  if (stats) {
    total = stats.total_alerts;
    openCount = stats.open_alerts;
    investigatingCount = stats.investigating_alerts;
    resolvedCount = stats.resolved_alerts;
    falsePosCount = stats.false_positive_alerts;
  } else {
    alerts.forEach(a => {
      const s = (a.status || "OPEN").toUpperCase();
      if (s === "OPEN") openCount++;
      else if (s === "INVESTIGATING" || s === "ACKNOWLEDGED") investigatingCount++;
      else if (s === "RESOLVED" || s === "COMPLETED") resolvedCount++;
      else if (s === "FALSE_POSITIVE") falsePosCount++;
    });
  }

  // Update KPI card counters
  const elTotal = document.getElementById("hist-stat-total");
  const elOpen = document.getElementById("hist-stat-open");
  const elInvest = document.getElementById("hist-stat-investigating");
  const elResolved = document.getElementById("hist-stat-resolved");
  const elFalsePos = document.getElementById("hist-stat-false-pos");

  if (elTotal) elTotal.textContent = total;
  if (elOpen) elOpen.textContent = openCount;
  if (elInvest) elInvest.textContent = investigatingCount;
  if (elResolved) elResolved.textContent = resolvedCount;
  if (elFalsePos) elFalsePos.textContent = falsePosCount;

  // Update tab badge counters
  const bAll = document.getElementById("badge-count-all");
  const bOpen = document.getElementById("badge-count-open");
  const bInvest = document.getElementById("badge-count-investigating");
  const bResolved = document.getElementById("badge-count-resolved");
  const bFalsePos = document.getElementById("badge-count-false-pos");

  if (bAll) bAll.textContent = total;
  if (bOpen) bOpen.textContent = openCount;
  if (bInvest) bInvest.textContent = investigatingCount;
  if (bResolved) bResolved.textContent = resolvedCount;
  if (bFalsePos) bFalsePos.textContent = falsePosCount;
}

window.setFilterStatus = function(status) {
  activeStatusFilter = status;
  updateTabVisuals(status);
  applyFilters();
};

function updateTabVisuals(status) {
  document.querySelectorAll(".status-tab-btn").forEach(btn => btn.classList.remove("active"));
  if (!status) {
    document.getElementById("tab-all")?.classList.add("active");
  } else if (status === "OPEN") {
    document.getElementById("tab-open")?.classList.add("active");
  } else if (status === "INVESTIGATING") {
    document.getElementById("tab-investigating")?.classList.add("active");
  } else if (status === "RESOLVED") {
    document.getElementById("tab-resolved")?.classList.add("active");
  } else if (status === "FALSE_POSITIVE") {
    document.getElementById("tab-false-pos")?.classList.add("active");
  }
}

window.resetFilters = function() {
  activeStatusFilter = "";
  updateTabVisuals("");
  const sSearch = document.getElementById("hist-filter-search");
  const sSev = document.getElementById("hist-filter-severity");
  const sSource = document.getElementById("hist-filter-source");

  if (sSearch) sSearch.value = "";
  if (sSev) sSev.value = "";
  if (sSource) sSource.value = "";

  applyFilters();
};

function applyFilters() {
  const sev = document.getElementById("hist-filter-severity")?.value || "";
  const source = document.getElementById("hist-filter-source")?.value || "";
  const search = document.getElementById("hist-filter-search")?.value.toLowerCase().trim() || "";

  let filtered = allAlertHistory.filter(a => {
    // Status Filter
    if (activeStatusFilter) {
      const aStatus = (a.status || "OPEN").toUpperCase();
      if (activeStatusFilter === "INVESTIGATING") {
        if (aStatus !== "INVESTIGATING" && aStatus !== "ACKNOWLEDGED") return false;
      } else if (activeStatusFilter === "RESOLVED") {
        if (aStatus !== "RESOLVED" && aStatus !== "COMPLETED") return false;
      } else if (aStatus !== activeStatusFilter) {
        return false;
      }
    }

    // Severity Filter
    if (sev && a.severity !== sev) return false;

    // Source Filter
    if (source && a.source !== source) return false;

    // Search Query Filter
    if (search) {
      const matchEmp = (a.employee_id || "").toLowerCase().includes(search);
      const matchUser = (a.employee_username || "").toLowerCase().includes(search);
      const matchType = (a.alert_type || "").toLowerCase().includes(search);
      const matchDesc = (a.description || "").toLowerCase().includes(search);
      const matchFile = (a.filename || "").toLowerCase().includes(search);
      if (!matchEmp && !matchUser && !matchType && !matchDesc && !matchFile) return false;
    }

    return true;
  });

  renderHistoryTable(filtered);
}

function renderHistoryTable(alerts) {
  const tbody = document.getElementById("hist-table-body");
  const countLabel = document.getElementById("table-record-count");
  if (!tbody) return;

  if (countLabel) countLabel.textContent = `${alerts.length} records`;

  if (alerts.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" class="text-center text-muted py-5">
          <i class="fas fa-folder-open fa-2x mb-2 d-block opacity-50"></i>
          No alert history records found matching filter criteria
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td>
        <span class="text-muted small">${formatDate(a.created_at)}</span>
      </td>
      <td>
        <span class="text-cyan fw-bold">${a.employee_id}</span>
        <div class="small text-muted">${a.employee_username || ''}</div>
      </td>
      <td>
        <div class="d-flex flex-column gap-1">
          ${formatAlertTypeBadge(a.alert_type)}
          <div class="small text-muted font-monospace" style="font-size: 0.72rem;">${a.alert_type}</div>
        </div>
      </td>
      <td>${formatSeverityBadge(a.severity)}</td>
      <td>
        <span class="text-white small fw-semibold">${a.filename || a.source || 'N/A'}</span>
        <div class="small text-muted">${a.source || 'System'}</div>
      </td>
      <td>${formatRiskBadge(a.risk_score)}</td>
      <td>
        ${formatAlertStatusBadge(a.status)}
      </td>
      <td>
        <button class="btn btn-sm btn-outline-info" onclick="viewHistoryAlertDetails(${a.id})">
          <i class="fas fa-magnifying-glass me-1"></i> Triage
        </button>
      </td>
    </tr>
  `).join("");
}

window.viewHistoryAlertDetails = function(alertId) {
  const alert = allAlertHistory.find(a => a.id === alertId);
  if (!alert) return;

  document.getElementById("modal-hist-id").textContent = `#${alert.id}`;
  document.getElementById("modal-hist-emp").textContent = `${alert.employee_id} ${alert.employee_username ? '(' + alert.employee_username + ')' : ''}`;
  document.getElementById("modal-hist-source").textContent = alert.source || "FILE_MONITOR";
  document.getElementById("modal-hist-sev").innerHTML = formatSeverityBadge(alert.severity);
  document.getElementById("modal-hist-risk").innerHTML = formatRiskBadge(alert.risk_score);
  document.getElementById("modal-hist-time").textContent = formatDate(alert.created_at);
  document.getElementById("modal-hist-current-status").innerHTML = formatAlertStatusBadge(alert.status);
  document.getElementById("modal-hist-desc").textContent = alert.description;

  const statusSelect = document.getElementById("modal-hist-status-select");
  if (statusSelect) {
    let currentVal = (alert.status || "OPEN").toUpperCase();
    if (currentVal === "ACKNOWLEDGED") currentVal = "INVESTIGATING";
    statusSelect.value = currentVal;
  }

  const saveBtn = document.getElementById("btn-save-hist-status");
  if (saveBtn) {
    saveBtn.onclick = async () => {
      const newStatus = statusSelect.value;
      saveBtn.disabled = true;
      saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Updating...';

      try {
        await API.patch(`/alerts/${alert.id}`, { status: newStatus });
        showToast(`Alert #${alert.id} status updated to ${newStatus}`, "success");
        bootstrap.Modal.getInstance(document.getElementById("alertHistoryModal")).hide();
        loadAlertHistory();
      } catch (err) {
        showToast("Failed to update status: " + err.message, "error");
      } finally {
        saveBtn.disabled = false;
        saveBtn.innerHTML = '<i class="fas fa-floppy-disk me-1"></i> Update Status';
      }
    };
  }

  const modal = new bootstrap.Modal(document.getElementById("alertHistoryModal"));
  modal.show();
};
