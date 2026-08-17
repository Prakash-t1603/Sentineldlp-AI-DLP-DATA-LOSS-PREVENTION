// Alerts Management Controller
let allAlerts = [];

document.addEventListener("DOMContentLoaded", () => {
  loadAlerts();

  // Polling every 3 seconds for real-time live alert stream
  setInterval(loadAlerts, 3000);

  document.getElementById("filter-severity")?.addEventListener("change", applyFilters);
  document.getElementById("filter-status")?.addEventListener("change", applyFilters);
  document.getElementById("filter-search")?.addEventListener("input", applyFilters);
});

async function loadAlerts() {
  try {
    const data = await API.get("/alerts");
    allAlerts = data || [];
    applyFilters();
  } catch (err) {
    console.debug("Alert polling update:", err.message);
  }
}

function applyFilters() {
  const sev = document.getElementById("filter-severity")?.value || "";
  const status = document.getElementById("filter-status")?.value || "";
  const search = document.getElementById("filter-search")?.value.toLowerCase().trim() || "";

  let filtered = allAlerts.filter(a => {
    if (sev && a.severity !== sev) return false;
    if (status && a.status !== status) return false;
    if (search) {
      const matchEmp = (a.employee_id || "").toLowerCase().includes(search);
      const matchType = (a.alert_type || "").toLowerCase().includes(search);
      const matchDesc = (a.description || "").toLowerCase().includes(search);
      if (!matchEmp && !matchType && !matchDesc) return false;
    }
    return true;
  });

  renderAlerts(filtered);
}

function renderAlerts(alerts) {
  const tbody = document.getElementById("alerts-table-body");
  if (!tbody) return;

  if (alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4">No alerts found matching filter criteria</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td class="text-muted small">${formatDate(a.created_at)}</td>
      <td>
        <span class="text-info fw-bold">${a.employee_id}</span>
        <div class="small text-muted">${a.employee_username || ''}</div>
      </td>
      <td>
        <div class="d-flex flex-column gap-1">
          ${formatAlertTypeBadge(a.alert_type)}
          <div class="small text-muted font-monospace">${a.alert_type}</div>
        </div>
      </td>
      <td>${formatSeverityBadge(a.severity)}</td>
      <td><span class="text-muted small">${a.filename || a.source || 'N/A'}</span></td>
      <td>${formatRiskBadge(a.risk_score)}</td>
      <td>
        ${formatAlertStatusBadge(a.status)}
      </td>
      <td>
        <button class="btn btn-sm btn-outline-info" onclick="viewAlertDetails(${a.id})">
          <i class="fas fa-magnifying-glass me-1"></i> Triage
        </button>
      </td>
    </tr>
  `).join("");
}

window.viewAlertDetails = function(alertId) {
  const alert = allAlerts.find(a => a.id === alertId);
  if (!alert) return;

  document.getElementById("modal-alert-id").textContent = `#${alert.id}`;
  document.getElementById("modal-alert-emp").textContent = alert.employee_id;
  document.getElementById("modal-alert-type").innerHTML = `${formatAlertTypeBadge(alert.alert_type)} <span class="ms-2 text-muted">(${alert.alert_type})</span>`;
  document.getElementById("modal-alert-sev").innerHTML = formatSeverityBadge(alert.severity);
  document.getElementById("modal-alert-risk").innerHTML = formatRiskBadge(alert.risk_score);
  document.getElementById("modal-alert-source").textContent = alert.source;
  document.getElementById("modal-alert-status").innerHTML = formatAlertStatusBadge(alert.status);
  document.getElementById("modal-alert-desc").textContent = alert.description;

  const statusSelect = document.getElementById("modal-status-select");
  if (statusSelect) {
    let currentVal = (alert.status || "OPEN").toUpperCase();
    if (currentVal === "ACKNOWLEDGED") currentVal = "INVESTIGATING";
    statusSelect.value = currentVal;
  }

  const saveBtn = document.getElementById("btn-save-alert-status");
  if (saveBtn) {
    saveBtn.onclick = async () => {
      const newStatus = statusSelect.value;
      try {
        await API.patch(`/alerts/${alert.id}`, { status: newStatus });
        showToast(`Alert #${alert.id} status updated to ${newStatus}`, "success");
        bootstrap.Modal.getInstance(document.getElementById("alertDetailModal")).hide();
        loadAlerts();
      } catch (err) {
        showToast("Error updating alert status: " + err.message, "error");
      }
    };
  }

  const modal = new bootstrap.Modal(document.getElementById("alertDetailModal"));
  modal.show();
};

window.clearAllAlerts = async function() {
  if (!confirm("Are you sure you want to remove ALL alert and incident records from the database?")) return;
  try {
    const res = await API.delete("/alerts/clear-all");
    showToast(res?.message || "All alert data removed successfully", "success");
    loadAlerts();
  } catch (err) {
    showToast("Error clearing alerts: " + err.message, "error");
  }
};

