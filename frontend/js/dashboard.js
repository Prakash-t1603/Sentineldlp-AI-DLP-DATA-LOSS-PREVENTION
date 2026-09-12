// SentinelDLP Unified SOC Dashboard Controller
let channelChart = null;
let riskChart = null;
let destChart = null;
let currentChannelFilter = "ALL";
let currentSearchFilter = "";
let cachedDLPEvents = [];
let cachedDashboardAlerts = [];
let selectedDashboardAlertIds = new Set();

function escapeHTML(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

document.addEventListener("DOMContentLoaded", () => {
  loadDashboardData();

  // Polling every 3.5 seconds for live real-time threat feed
  setInterval(loadDashboardData, 3500);
});

async function loadDashboardData() {
  try {
    // 1. Fetch consolidated DLP statistics, SOC summary, events, alerts, and endpoint fleet
    const [dlpStats, dlpEvents, topEmps, alertsData, fleetStatus, fleetDevices] = await Promise.all([
      API.get("/dlp/statistics").catch(() => null),
      API.get("/dlp/events?limit=50").catch(() => []),
      API.get("/dashboard/summary").catch(() => null),
      API.get("/alerts").catch(() => []),
      API.get("/agents/status").catch(() => null),
      API.get("/agents").catch(() => null)
    ]);

    if (fleetStatus || dlpStats) {
      renderEnterpriseFleetKPIs(fleetStatus, dlpStats, alertsData);
    }

    if (dlpStats) {
      renderDLPCharts(dlpStats);
      renderTopSensitiveFiles(dlpStats.top_sensitive_files);
    }

    if (fleetDevices) {
      renderFleetDevices(fleetDevices);
    }

    if (dlpEvents && Array.isArray(dlpEvents)) {
      cachedDLPEvents = dlpEvents;
      renderUnifiedDLPEventsTable(dlpEvents);
      checkLiveCriticalBanner(dlpEvents);
    }

    if (alertsData && Array.isArray(alertsData)) {
      cachedDashboardAlerts = alertsData;
      renderDashboardAlerts(alertsData);
    }

    if (topEmps) {
      renderTopEmployees(topEmps.top_risk_employees);
      renderRecentActivities(topEmps.recent_activities);
    }
  } catch (err) {
    console.debug("Dashboard data load tick:", err.message);
  }
}

function renderEnterpriseFleetKPIs(fleetStatus, dlpStats, alerts) {
  const setVal = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val !== undefined ? val : 0;
  };

  if (fleetStatus) {
    setVal("kpi-total-employees", fleetStatus.total_employees);
    setVal("kpi-live-employees", fleetStatus.live_employees);
    setVal("kpi-warning-employees", fleetStatus.warning_employees);
    setVal("kpi-offline-employees", fleetStatus.offline_employees);
    setVal("kpi-monitoring-active", fleetStatus.monitoring_active_employees);
  } else if (dlpStats) {
    setVal("kpi-total-employees", dlpStats.total_dlp_events || 0);
  }

  setVal("kpi-total-alerts", alerts ? alerts.length : 0);
  setVal("kpi-critical-incidents", dlpStats ? dlpStats.critical_incidents : 0);
}

function renderDLPCharts(stats) {
  // 1. Events by Channel Chart
  const chanLabels = stats.events_by_channel.map(c => c.label);
  const chanCounts = stats.events_by_channel.map(c => c.count);
  const chanColors = ["#ef4444", "#0284c7", "#06b6d4", "#a855f7"];

  const ctxChan = document.getElementById("chart-channel-dist")?.getContext("2d");
  if (ctxChan) {
    if (channelChart) channelChart.destroy();
    channelChart = new Chart(ctxChan, {
      type: "doughnut",
      data: {
        labels: chanLabels,
        datasets: [{
          data: chanCounts.every(c => c === 0) ? [1] : chanCounts,
          backgroundColor: chanCounts.every(c => c === 0) ? ["#334155"] : chanColors,
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#94a3b8", boxWidth: 10, font: { size: 11 } } }
        },
        cutout: "70%"
      }
    });
  }

  // 2. Risk Distribution Chart
  const riskLabels = stats.risk_distribution.map(d => d.label);
  const riskCounts = stats.risk_distribution.map(d => d.count);
  const riskColors = ["#10b981", "#f59e0b", "#f97316", "#ef4444"];

  const ctxRisk = document.getElementById("chart-risk-dist")?.getContext("2d");
  if (ctxRisk) {
    if (riskChart) riskChart.destroy();
    riskChart = new Chart(ctxRisk, {
      type: "doughnut",
      data: {
        labels: riskLabels,
        datasets: [{
          data: riskCounts.every(c => c === 0) ? [1] : riskCounts,
          backgroundColor: riskCounts.every(c => c === 0) ? ["#334155"] : riskColors,
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#94a3b8", boxWidth: 10, font: { size: 11 } } }
        },
        cutout: "70%"
      }
    });
  }

  // 3. Top Destinations Bar Chart
  const destLabels = stats.top_destinations.map(d => d.label);
  const destCounts = stats.top_destinations.map(d => d.count);

  const ctxDest = document.getElementById("chart-top-destinations")?.getContext("2d");
  if (ctxDest) {
    if (destChart) destChart.destroy();
    destChart = new Chart(ctxDest, {
      type: "bar",
      data: {
        labels: destLabels.length > 0 ? destLabels : ["No destinations yet"],
        datasets: [{
          label: "Transfers Count",
          data: destCounts.length > 0 ? destCounts : [0],
          backgroundColor: "#38bdf8",
          borderRadius: 4
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
          x: { ticks: { color: "#94a3b8", stepSize: 1 }, grid: { color: "rgba(255, 255, 255, 0.05)" } },
          y: { ticks: { color: "#cbd5e1", font: { size: 11 } }, grid: { display: false } }
        }
      }
    });
  }
}

function filterEventsByChannel(channel) {
  currentChannelFilter = channel;
  document.querySelectorAll(".btn-channel-filter").forEach(b => {
    if (b.getAttribute("data-channel") === channel) {
      b.classList.add("active");
    } else {
      b.classList.remove("active");
    }
  });
  renderUnifiedDLPEventsTable(cachedDLPEvents);
}

function filterEventsSearch(query) {
  currentSearchFilter = (query || "").trim().toLowerCase();
  renderUnifiedDLPEventsTable(cachedDLPEvents);
}

function renderUnifiedDLPEventsTable(events) {
  const tbody = document.getElementById("table-unified-dlp-events");
  if (!tbody) return;

  let filtered = events;
  if (currentChannelFilter !== "ALL") {
    filtered = filtered.filter(e => (e.channel || "").toUpperCase() === currentChannelFilter);
  }

  if (currentSearchFilter) {
    filtered = filtered.filter(e =>
      (e.file_name || "").toLowerCase().includes(currentSearchFilter) ||
      (e.employee_id || "").toLowerCase().includes(currentSearchFilter) ||
      (e.destination || "").toLowerCase().includes(currentSearchFilter) ||
      (e.application || "").toLowerCase().includes(currentSearchFilter) ||
      (e.action || "").toLowerCase().includes(currentSearchFilter)
    );
  }

  if (!filtered || filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" class="text-center text-muted py-4">No DLP events matching the selected filter criteria</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.slice(0, 30).map(e => `
    <tr>
      <td><span class="text-muted small">${formatDate(e.timestamp)}</span></td>
      <td><span class="fw-bold text-info font-monospace">${e.employee_id}</span></td>
      <td>${formatChannelBadge(e.channel)}</td>
      <td><span class="text-white small fw-semibold">${e.application || 'N/A'}</span></td>
      <td>
        <div class="fw-bold text-white text-truncate" style="max-width: 180px;" title="${e.file_name}">
          <i class="fas fa-file-lines text-muted me-1"></i>${e.file_name}
        </div>
        <div class="text-muted" style="font-size: 0.72rem;">${(e.file_size / 1024).toFixed(1)} KB</div>
      </td>
      <td><span class="badge bg-dark border border-secondary text-truncate" style="max-width: 150px;" title="${e.destination || 'N/A'}">${e.destination || 'N/A'}</span></td>
      <td>${formatRiskBadge(e.risk_score)}</td>
      <td>${formatActionBadge(e.action)}</td>
      <td><span class="badge ${e.status === 'BLOCKED' ? 'bg-danger' : (e.status === 'WARNED' ? 'bg-warning text-dark' : 'bg-success')}">${e.status}</span></td>
      <td><span class="small text-muted text-truncate d-inline-block" style="max-width: 220px;" title="${e.details || ''}">${e.details || 'Scanned Clean'}</span></td>
    </tr>
  `).join("");
}

function renderTopSensitiveFiles(files) {
  const tbody = document.getElementById("table-top-sensitive-files");
  if (!tbody) return;

  if (!files || files.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted py-3">No sensitive files flagged yet</td></tr>`;
    return;
  }

  tbody.innerHTML = files.map(f => `
    <tr>
      <td><div class="fw-semibold text-white text-truncate" style="max-width: 160px;" title="${f.file_name}">${f.file_name}</div></td>
      <td>${formatChannelBadge(f.channel)}</td>
      <td>${formatRiskBadge(f.risk_score)}</td>
      <td>${formatActionBadge(f.action)}</td>
    </tr>
  `).join("");
}

function renderTopEmployees(employees) {
  const tbody = document.getElementById("table-top-employees");
  if (!tbody) return;

  if (!employees || employees.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted py-3">No endpoints registered yet</td></tr>`;
    return;
  }

  tbody.innerHTML = employees.map(emp => `
    <tr>
      <td>
        <div class="fw-bold text-white">${emp.username}</div>
        <div class="small text-muted font-monospace">${emp.employee_id}</div>
      </td>
      <td><span class="badge bg-dark border border-secondary">${emp.hostname}</span></td>
      <td>${formatRiskBadge(emp.risk_score)}</td>
      <td>${formatStatusDot(emp.status || 'ONLINE')}</td>
      <td>
        <a href="/employees?id=${emp.employee_id}" class="btn btn-sm btn-outline-info py-0 px-2" style="font-size: 0.75rem;">
          Profile
        </a>
      </td>
    </tr>
  `).join("");
}

function renderRecentActivities(activities) {
  const container = document.getElementById("timeline-recent-activity");
  if (!container) return;

  if (!activities || activities.length === 0) {
    container.innerHTML = `<div class="text-muted text-center py-3">No activity logs recorded yet</div>`;
    return;
  }

  container.innerHTML = activities.slice(0, 6).map(act => {
    let icon = "fa-file-alt text-info";
    const actType = act.activity_type || "";
    if (actType.includes("USB")) icon = "fa-usb text-danger";
    else if (actType.includes("MESSAGING") || actType.includes("WHATSAPP")) icon = "fa-brands fa-whatsapp text-success";
    else if (actType.includes("WEB_STORAGE") || actType.includes("CLOUD")) icon = "fa-cloud-arrow-up text-primary";
    else if (actType.includes("EMAIL")) icon = "fa-envelope text-info";
    else if (actType.includes("CLIPBOARD")) icon = "fa-clipboard text-warning";

    return `
      <div class="d-flex align-items-center justify-content-between py-2 border-bottom border-secondary border-opacity-25">
        <div class="d-flex align-items-center gap-2">
          <i class="fas ${icon}"></i>
          <div>
            <div class="text-white small fw-bold">${act.activity_type}: <span class="text-muted">${act.destination || act.filepath || act.process_name || 'N/A'}</span></div>
            <div class="text-muted" style="font-size: 0.75rem">${act.employee_id} • ${formatDate(act.timestamp)}</div>
          </div>
        </div>
        <div>
          ${formatRiskBadge(act.risk_score)}
        </div>
      </div>
    `;
  }).join("");
}

function checkLiveCriticalBanner(events) {
  const banner = document.getElementById("dlp-live-alert-banner");
  if (!banner || !events || events.length === 0) return;

  const latest = events[0];
  if (latest && (latest.action === "BLOCK" || latest.risk_level === "CRITICAL")) {
    const diffSecs = (new Date().getTime() - new Date(latest.timestamp).getTime()) / 1000;
    if (diffSecs < 12) { // Recent in last 12 seconds
      const title = document.getElementById("banner-alert-title");
      const desc = document.getElementById("banner-alert-desc");
      if (title) title.textContent = `🚨 REAL-TIME DLP INTERCEPTION: [${latest.action}] on ${latest.channel}`;
      if (desc) desc.textContent = `Attempted transfer of '${latest.file_name}' to '${latest.destination}' intercepted. Risk: ${latest.risk_score} (${latest.risk_level}).`;
      banner.classList.remove("d-none");
    }
  }
}

function renderDashboardAlerts(alerts) {
  const countBadge = document.getElementById("dash-alerts-count");
  if (countBadge) {
    countBadge.textContent = `${alerts.length} Alert${alerts.length === 1 ? '' : 's'}`;
  }

  const tbody = document.getElementById("table-dashboard-alerts");
  if (!tbody) return;

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" class="text-center text-muted py-4"><i class="fas fa-shield-check text-success me-2"></i>No active security alerts in the system</td></tr>`;
    updateDashboardAlertSelectionUI();
    return;
  }

  tbody.innerHTML = alerts.map(a => {
    const isSelected = selectedDashboardAlertIds.has(a.id);
    return `
      <tr class="${isSelected ? 'table-active' : ''}">
        <td class="text-center">
          <input type="checkbox" class="form-check-input bg-dark border-secondary alert-select-cb" data-alert-id="${a.id}" ${isSelected ? 'checked' : ''} onchange="toggleSelectDashboardAlert(${a.id}, this.checked)">
        </td>
        <td><span class="text-muted small">${formatDate(a.created_at)}</span></td>
        <td>
          <span class="fw-bold text-info font-monospace">${a.employee_id}</span>
          <div class="text-muted" style="font-size: 0.72rem;">${a.employee_username || ''}</div>
        </td>
        <td>
          <span class="badge bg-dark border border-secondary text-white font-monospace">${a.alert_type}</span>
        </td>
        <td><span class="badge bg-secondary bg-opacity-25 text-white">${a.source || 'N/A'}</span></td>
        <td>${formatSeverityBadge(a.severity)}</td>
        <td>${formatRiskBadge(a.risk_score)}</td>
        <td>${formatAlertStatusBadge(a.status)}</td>
        <td>
          <div class="text-white small text-truncate" style="max-width: 260px;" title="${a.description}">
            ${a.description}
          </div>
        </td>
        <td class="text-center">
          <div class="d-flex align-items-center justify-content-center gap-1">
            <button type="button" class="btn btn-sm btn-outline-danger py-0 px-2" onclick="deleteSingleDashboardAlert(${a.id})" title="Delete Alert #${a.id}">
              <i class="fas fa-trash-can"></i>
            </button>
            <a href="/alerts" class="btn btn-sm btn-outline-info py-0 px-2" title="Triage on Alerts page">
              <i class="fas fa-magnifying-glass"></i>
            </a>
          </div>
        </td>
      </tr>
    `;
  }).join("");

  updateDashboardAlertSelectionUI();
}

window.toggleSelectDashboardAlert = function(id, isChecked) {
  if (isChecked) {
    selectedDashboardAlertIds.add(id);
  } else {
    selectedDashboardAlertIds.delete(id);
  }
  updateDashboardAlertSelectionUI();
};

window.toggleSelectAllDashboardAlerts = function(isChecked) {
  if (isChecked) {
    cachedDashboardAlerts.forEach(a => selectedDashboardAlertIds.add(a.id));
  } else {
    selectedDashboardAlertIds.clear();
  }
  renderDashboardAlerts(cachedDashboardAlerts);
};

function updateDashboardAlertSelectionUI() {
  const count = selectedDashboardAlertIds.size;
  const countSpan = document.getElementById("dash-selected-count");
  const btnDelete = document.getElementById("btn-delete-selected-dash-alerts");
  const selectAll = document.getElementById("select-all-dash-alerts");

  if (countSpan) countSpan.textContent = count;
  if (btnDelete) {
    if (count > 0) {
      btnDelete.classList.remove("d-none");
    } else {
      btnDelete.classList.add("d-none");
    }
  }
  if (selectAll) {
    selectAll.checked = cachedDashboardAlerts.length > 0 && selectedDashboardAlertIds.size === cachedDashboardAlerts.length;
  }
}

window.deleteSingleDashboardAlert = async function(alertId) {
  if (!confirm(`Are you sure you want to delete Alert #${alertId}?`)) return;
  try {
    await API.delete(`/alerts/${alertId}`);
    selectedDashboardAlertIds.delete(alertId);
    showToast(`Alert #${alertId} deleted successfully`, "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error deleting alert: " + err.message, "error");
  }
};

window.deleteSelectedDashboardAlerts = async function() {
  const ids = Array.from(selectedDashboardAlertIds);
  if (ids.length === 0) return;
  if (!confirm(`Are you sure you want to delete ${ids.length} selected alert(s)?`)) return;

  try {
    const res = await API.post("/alerts/bulk-delete", { alert_ids: ids });
    selectedDashboardAlertIds.clear();
    showToast(res.message || `Deleted ${ids.length} alert(s)`, "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error deleting selected alerts: " + err.message, "error");
  }
};

window.clearAllDashboardAlerts = async function() {
  if (!confirm("Are you sure you want to remove ALL alert and incident records from the database?")) return;
  try {
    const res = await API.delete("/alerts/clear-all");
    selectedDashboardAlertIds.clear();
    showToast(res?.message || "All alert data removed successfully", "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error clearing alerts: " + err.message, "error");
  }
};

function renderFleetDevices(fleetData) {
  if (!fleetData) return;

  const totalEl = document.getElementById("fleet-total-count");
  const onlineEl = document.getElementById("fleet-online-count");
  const warningEl = document.getElementById("fleet-warning-count");
  const offlineEl = document.getElementById("fleet-offline-count");

  if (totalEl) totalEl.textContent = `${fleetData.total_devices || 0} Devices`;
  if (onlineEl) onlineEl.textContent = fleetData.online_devices || 0;
  if (warningEl) warningEl.textContent = fleetData.warning_devices || 0;
  if (offlineEl) offlineEl.textContent = fleetData.offline_devices || 0;

  const tbody = document.getElementById("table-fleet-devices");
  if (!tbody) return;

  const devices = fleetData.devices || [];
  if (devices.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-3">No endpoint agents registered yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = devices.map(d => {
    let statusBadge = "";
    if (d.status === "ONLINE") {
      statusBadge = `<span class="badge bg-success bg-opacity-25 text-success border border-success"><i class="fas fa-circle-dot text-success me-1"></i> LIVE</span>`;
    } else if (d.status === "WARNING") {
      statusBadge = `<span class="badge bg-warning bg-opacity-25 text-warning border border-warning"><i class="fas fa-triangle-exclamation text-warning me-1"></i> WARNING</span>`;
    } else {
      statusBadge = `<span class="badge bg-danger bg-opacity-25 text-danger border border-danger"><i class="fas fa-circle-xmark text-danger me-1"></i> OFFLINE</span>`;
    }

    const lastSeenText = d.last_seen_seconds_ago !== null && d.last_seen_seconds_ago !== undefined
      ? (d.last_seen_seconds_ago < 60 ? `${Math.round(d.last_seen_seconds_ago)}s ago` : `${Math.round(d.last_seen_seconds_ago / 60)}m ago`)
      : "Never";

    // Monitoring modules indicators
    const isLive = d.status === "ONLINE";
    const modBadges = `
      <div class="d-flex flex-wrap gap-1" style="font-size: 0.68rem;">
        <span class="badge ${isLive ? 'bg-success' : 'bg-secondary'} bg-opacity-25 ${isLive ? 'text-success' : 'text-muted'} border ${isLive ? 'border-success' : 'border-secondary'}">USB</span>
        <span class="badge ${isLive ? 'bg-success' : 'bg-secondary'} bg-opacity-25 ${isLive ? 'text-success' : 'text-muted'} border ${isLive ? 'border-success' : 'border-secondary'}">File</span>
        <span class="badge ${isLive ? 'bg-success' : 'bg-secondary'} bg-opacity-25 ${isLive ? 'text-success' : 'text-muted'} border ${isLive ? 'border-success' : 'border-secondary'}">Clip</span>
        <span class="badge ${isLive ? 'bg-success' : 'bg-secondary'} bg-opacity-25 ${isLive ? 'text-success' : 'text-muted'} border ${isLive ? 'border-success' : 'border-secondary'}">Proc</span>
        <span class="badge ${isLive ? 'bg-success' : 'bg-secondary'} bg-opacity-25 ${isLive ? 'text-success' : 'text-muted'} border ${isLive ? 'border-success' : 'border-secondary'}">Web</span>
        <span class="badge ${isLive ? 'bg-success' : 'bg-secondary'} bg-opacity-25 ${isLive ? 'text-success' : 'text-muted'} border ${isLive ? 'border-success' : 'border-secondary'}">Mail</span>
      </div>
    `;

    return `
      <tr>
        <td>${statusBadge}</td>
        <td>
          <div class="fw-bold text-white">${escapeHTML(d.employee_name || d.employee_username || d.employee_id || "Unassigned")}</div>
          <div class="small text-muted font-monospace">${escapeHTML(d.employee_id || "EMP-000")}</div>
        </td>
        <td class="fw-bold font-monospace text-cyan">${escapeHTML(d.device_id)}</td>
        <td>
          <div class="text-white small">${escapeHTML(d.hostname || "-")}</div>
          <div class="text-muted font-monospace" style="font-size: 0.72rem;">${escapeHTML(d.ip_address || "127.0.0.1")}</div>
        </td>
        <td class="small text-muted">${escapeHTML(d.operating_system || "Unknown")}</td>
        <td>${modBadges}</td>
        <td class="small text-muted font-monospace"><i class="fas fa-heart-pulse text-info me-1"></i>${lastSeenText}</td>
        <td class="text-center">
          <a href="/employees?id=${d.employee_id || ''}" class="btn btn-sm btn-outline-info py-0 px-2" style="font-size: 0.75rem;">
            <i class="fas fa-id-card me-1"></i> Profile
          </a>
        </td>
      </tr>
    `;
  }).join("");
}

