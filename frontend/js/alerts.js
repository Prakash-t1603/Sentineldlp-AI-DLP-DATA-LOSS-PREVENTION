// Alerts Management Controller
let allAlerts = [];
let selectedAlertIds = new Set();

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
    tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted py-4"><i class="fas fa-shield-check text-success me-2"></i>No alerts found matching filter criteria</td></tr>`;
    updateAlertSelectionUI(alerts);
    return;
  }

  tbody.innerHTML = alerts.map(a => {
    const isSelected = selectedAlertIds.has(a.id);
    return `
      <tr class="${isSelected ? 'table-active' : ''}">
        <td class="text-center">
          <input type="checkbox" class="form-check-input bg-dark border-secondary alert-row-cb" data-alert-id="${a.id}" ${isSelected ? 'checked' : ''} onchange="toggleSelectAlert(${a.id}, this.checked)">
        </td>
        <td class="text-muted small">${formatDate(a.created_at)}</td>
        <td>
          <span class="text-info fw-bold font-monospace">${a.employee_id}</span>
          <div class="small text-muted">${a.employee_username || ''}</div>
        </td>
        <td>
          <div class="d-flex flex-column gap-1">
            ${formatAlertTypeBadge(a.alert_type)}
            <div class="small text-muted font-monospace">${a.alert_type}</div>
          </div>
        </td>
        <td>${formatSeverityBadge(a.severity)}</td>
        <td><span class="text-muted small text-truncate d-inline-block" style="max-width: 140px;" title="${a.filename || a.source || 'N/A'}">${a.filename || a.source || 'N/A'}</span></td>
        <td>${formatRiskBadge(a.risk_score)}</td>
        <td>
          ${formatAlertStatusBadge(a.status)}
        </td>
        <td class="text-center">
          <div class="d-flex align-items-center justify-content-center gap-1">
            <button class="btn btn-sm btn-outline-info py-0 px-2" onclick="viewAlertDetails(${a.id})" title="Triage Alert">
              <i class="fas fa-magnifying-glass"></i>
            </button>
            <button class="btn btn-sm btn-outline-danger py-0 px-2" onclick="deleteSingleAlert(${a.id})" title="Delete Alert #${a.id}">
              <i class="fas fa-trash-can"></i>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");

  updateAlertSelectionUI(alerts);
}

window.toggleSelectAlert = function(id, isChecked) {
  if (isChecked) {
    selectedAlertIds.add(id);
  } else {
    selectedAlertIds.delete(id);
  }
  updateAlertSelectionUI();
};

window.toggleSelectAllAlerts = function(isChecked) {
  if (isChecked) {
    allAlerts.forEach(a => selectedAlertIds.add(a.id));
  } else {
    selectedAlertIds.clear();
  }
  applyFilters();
};

function updateAlertSelectionUI(currentAlertsList) {
  const count = selectedAlertIds.size;
  const countSpan = document.getElementById("selected-alerts-count");
  const btnDelete = document.getElementById("btn-delete-selected-alerts");
  const selectAll = document.getElementById("select-all-alerts");

  if (countSpan) countSpan.textContent = count;
  if (btnDelete) {
    if (count > 0) {
      btnDelete.classList.remove("d-none");
    } else {
      btnDelete.classList.add("d-none");
    }
  }
  if (selectAll) {
    const list = currentAlertsList || allAlerts;
    selectAll.checked = list.length > 0 && selectedAlertIds.size === list.length;
  }
}

window.deleteSingleAlert = async function(alertId) {
  if (!confirm(`Are you sure you want to delete Alert #${alertId}?`)) return;
  try {
    await API.delete(`/alerts/${alertId}`);
    selectedAlertIds.delete(alertId);
    showToast(`Alert #${alertId} deleted successfully`, "success");
    await loadAlerts();
  } catch (err) {
    showToast("Error deleting alert: " + err.message, "error");
  }
};

window.deleteSelectedAlerts = async function() {
  const ids = Array.from(selectedAlertIds);
  if (ids.length === 0) return;
  if (!confirm(`Are you sure you want to delete ${ids.length} selected alert(s)?`)) return;

  try {
    const res = await API.post("/alerts/bulk-delete", { alert_ids: ids });
    selectedAlertIds.clear();
    showToast(res.message || `Deleted ${ids.length} alert(s)`, "success");
    await loadAlerts();
  } catch (err) {
    showToast("Error deleting selected alerts: " + err.message, "error");
  }
};

window.viewAlertDetails = function(alertId) {
  const alert = allAlerts.find(a => a.id === alertId);
  if (!alert) return;

  document.getElementById("modal-alert-id").textContent = `#${alert.id}`;
  document.getElementById("modal-alert-emp").textContent = alert.employee_id;
  document.getElementById("modal-alert-sev").innerHTML = formatSeverityBadge(alert.severity);
  document.getElementById("modal-alert-risk").innerHTML = formatRiskBadge(alert.risk_score);
  document.getElementById("modal-alert-source").textContent = alert.source;
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
    selectedAlertIds.clear();
    showToast(res?.message || "All alert data removed successfully", "success");
    loadAlerts();
  } catch (err) {
    showToast("Error clearing alerts: " + err.message, "error");
  }
};


