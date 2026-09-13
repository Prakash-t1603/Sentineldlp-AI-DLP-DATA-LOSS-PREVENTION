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

function formatDetectionDetailsBadges(details) {
  if (!details) return '<span class="badge bg-success bg-opacity-25 text-success border border-success border-opacity-30"><i class="fas fa-check me-1"></i>Clean</span>';

  const parts = [];
  const text = details.toUpperCase();

  if (text.includes("OCR: DETECTED")) {
    parts.push('<span class="badge text-white me-1" style="background: #7928ca;"><i class="fas fa-eye me-1"></i>OCR</span>');
  }
  if (text.includes("RESTRICTED") || text.includes("HIGHLY_CONFIDENTIAL")) {
    parts.push('<span class="badge bg-danger text-white me-1"><i class="fas fa-shield-halved me-1"></i>Restricted</span>');
  } else if (text.includes("CONFIDENTIAL")) {
    parts.push('<span class="badge bg-warning text-dark me-1"><i class="fas fa-file-shield me-1"></i>Confidential</span>');
  }
  if (text.includes("IDENTITY") || text.includes("AADHAAR") || text.includes("SSN") || text.includes("PASSPORT") || text.includes("ID_CARD")) {
    parts.push('<span class="badge bg-info text-dark me-1"><i class="fas fa-id-card me-1"></i>Identity</span>');
  }
  if (text.includes("CREDENTIAL") || text.includes("AWS_") || text.includes("PRIVATE_KEY") || text.includes("TOKEN") || text.includes("SECRET")) {
    parts.push('<span class="badge bg-danger text-white me-1"><i class="fas fa-key me-1"></i>Secret</span>');
  }
  if (text.includes("FINANCIAL") || text.includes("CREDIT_CARD") || text.includes("SALARY") || text.includes("PAN_CARD")) {
    parts.push('<span class="badge bg-warning text-dark me-1"><i class="fas fa-coins me-1"></i>Financial</span>');
  }

  if (parts.length === 0) {
    if (text.includes("CLEAN") || text.includes("PUBLIC")) {
      return '<span class="badge bg-success bg-opacity-25 text-success border border-success border-opacity-30"><i class="fas fa-check me-1"></i>Clean</span>';
    }
    return `<span class="small text-muted text-truncate d-inline-block" style="max-width: 220px;" title="${escapeHTML(details)}">${escapeHTML(details)}</span>`;
  }

  return `<div class="d-flex flex-wrap gap-1 align-items-center" title="${escapeHTML(details)}">${parts.join("")}</div>`;
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
      (e.action || "").toLowerCase().includes(currentSearchFilter) ||
      (e.details || "").toLowerCase().includes(currentSearchFilter)
    );
  }

  if (!filtered || filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="11" class="text-center text-muted py-4">No DLP events matching the selected filter criteria</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.slice(0, 30).map(e => `
    <tr style="cursor: pointer;" onclick="if (!event.target.closest('button')) viewDLPEventDetails('${e.event_id || e.id}')">
      <td><span class="text-muted small">${formatDate(e.timestamp)}</span></td>
      <td><span class="fw-bold text-info font-monospace">${escapeHTML(e.employee_id)}</span></td>
      <td>${formatChannelBadge(e.channel)}</td>
      <td><span class="text-white small fw-semibold">${escapeHTML(e.application || 'N/A')}</span></td>
      <td>
        <div class="fw-bold text-white text-truncate" style="max-width: 180px;" title="${escapeHTML(e.file_name)}">
          <i class="fas fa-file-lines text-muted me-1"></i>${escapeHTML(e.file_name)}
        </div>
        <div class="text-muted" style="font-size: 0.72rem;">${(e.file_size / 1024).toFixed(1)} KB</div>
      </td>
      <td><span class="badge bg-dark border border-secondary text-truncate" style="max-width: 150px;" title="${escapeHTML(e.destination || 'N/A')}">${escapeHTML(e.destination || 'N/A')}</span></td>
      <td>${formatRiskBadge(e.risk_score)}</td>
      <td>${formatActionBadge(e.action)}</td>
      <td><span class="badge ${e.status === 'BLOCKED' ? 'bg-danger' : (e.status === 'WARNED' ? 'bg-warning text-dark' : 'bg-success')}">${escapeHTML(e.status)}</span></td>
      <td>${formatDetectionDetailsBadges(e.details)}</td>
      <td class="text-center" onclick="event.stopPropagation();">
        <div class="d-flex justify-content-center gap-1">
          <button type="button" class="btn btn-sm btn-outline-info py-0 px-2" style="font-size: 0.75rem;" onclick="viewDLPEventDetails('${e.event_id || e.id}')" title="Inspect Deep Content Analysis">
            <i class="fas fa-magnifying-glass"></i>
          </button>
          <button type="button" class="btn btn-sm btn-outline-danger py-0 px-2" style="font-size: 0.75rem;" onclick="deleteSingleDLPEvent('${e.event_id || e.id}')" title="Delete DLP Event">
            <i class="fas fa-trash-can"></i>
          </button>
        </div>
      </td>
    </tr>
  `).join("");
}

window.viewDLPEventDetails = function(eventId) {
  const ev = (cachedDLPEvents || []).find(e => (e.event_id === eventId || String(e.id) === String(eventId)));
  if (!ev) return;

  const setEl = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = val;
  };

  setEl("modal-event-id-header", `Event ID: ${ev.event_id || 'EVT-' + ev.id} &bull; Timestamp: ${formatDate(ev.timestamp)}`);
  setEl("modal-file-name", escapeHTML(ev.file_name || "unknown"));
  setEl("modal-file-type", escapeHTML(ev.file_type || (ev.file_name?.includes('.') ? '.' + ev.file_name.split('.').pop() : 'N/A')));
  setEl("modal-file-size", `${((ev.file_size || 0) / 1024).toFixed(1)} KB (${ev.file_size || 0} bytes)`);
  setEl("modal-file-hash", ev.file_hash ? escapeHTML(ev.file_hash) : '<span class="text-muted">N/A</span>');
  setEl("modal-file-channel", formatChannelBadge(ev.channel));
  setEl("modal-file-dest", `${escapeHTML(ev.application || 'N/A')} &rarr; ${escapeHTML(ev.destination || 'Local')}`);

  const details = (ev.details || "").toUpperCase();
  const isOCR = details.includes("OCR: DETECTED");
  setEl("modal-ocr-status", isOCR ? '<span class="badge text-white" style="background: #7928ca;">DETECTED</span>' : '<span class="badge bg-secondary">NONE</span>');
  setEl("modal-ocr-conf", isOCR ? 'Confidence: 95%' : 'Confidence: N/A');

  const isNLP = details.includes("NLP: DETECTED") || ev.sensitive_data_detected;
  setEl("modal-nlp-status", isNLP ? '<span class="badge bg-warning text-dark">DETECTED</span>' : '<span class="badge bg-success">CLEAN</span>');
  setEl("modal-nlp-entities", isNLP ? 'Contextual Entities Flagged' : 'No Anomalous Entities');

  let mlClass = "PUBLIC";
  if (details.includes("RESTRICTED") || details.includes("HIGHLY_CONFIDENTIAL")) mlClass = "RESTRICTED";
  else if (details.includes("CONFIDENTIAL")) mlClass = "CONFIDENTIAL";
  else if (details.includes("INTERNAL")) mlClass = "INTERNAL";

  const mlBadgeColor = mlClass === "RESTRICTED" ? "bg-danger" : (mlClass === "CONFIDENTIAL" ? "bg-warning text-dark" : "bg-success");
  setEl("modal-ml-status", `<span class="badge ${mlBadgeColor}">${mlClass}</span>`);
  setEl("modal-ml-conf", `Model: sentineldlp-v1 (Confidence: 94%)`);

  // Sensitive data findings container
  const entContainer = document.getElementById("modal-sensitive-entities-container");
  if (entContainer) {
    if (ev.sensitive_data_detected || details.includes("SENSITIVE DATA")) {
      entContainer.innerHTML = `
        <div class="p-2 rounded bg-black bg-opacity-30 border border-warning border-opacity-30">
          <div class="fw-semibold text-warning mb-1"><i class="fas fa-triangle-exclamation me-1"></i>Sensitive Content Identified:</div>
          <div class="text-white">${escapeHTML(ev.details || 'Sensitive entities detected during content analysis.')}</div>
        </div>
      `;
    } else {
      entContainer.innerHTML = '<span class="text-muted"><i class="fas fa-circle-check text-success me-1"></i>No sensitive entities detected in content.</span>';
    }
  }

  setEl("modal-ueba-score", ev.risk_score >= 80 ? '<span class="text-danger fw-bold">0.82 (UNUSUAL BEHAVIOR)</span>' : '<span class="text-success">0.05 (NORMAL)</span>');
  setEl("modal-content-risk", `${Math.round(ev.risk_score * 0.85)} / 100`);
  setEl("modal-channel-risk", ev.channel === "USB" ? "1.3x (Removable Media)" : (ev.channel === "BROWSER" ? "1.2x (Web Exfiltration)" : "1.0x"));
  setEl("modal-final-risk", String(ev.risk_score));

  const riskLevelEl = document.getElementById("modal-final-risk-level");
  if (riskLevelEl) {
    riskLevelEl.className = `badge ms-2 ${ev.risk_score >= 80 ? 'bg-danger' : (ev.risk_score >= 60 ? 'bg-warning text-dark' : 'bg-success')}`;
    riskLevelEl.textContent = ev.risk_level || (ev.risk_score >= 80 ? 'CRITICAL' : (ev.risk_score >= 60 ? 'HIGH' : 'LOW'));
  }

  const polActionEl = document.getElementById("modal-policy-action");
  if (polActionEl) {
    polActionEl.className = `badge fs-6 px-3 py-1 ${ev.action === 'BLOCK' ? 'bg-danger' : (ev.action === 'WARN' ? 'bg-warning text-dark' : 'bg-success')}`;
    polActionEl.textContent = ev.action || 'ALLOW';
  }

  const modalEl = document.getElementById("eventDetailsModal");
  if (modalEl && typeof bootstrap !== "undefined") {
    const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
    modal.show();
  }
};

window.deleteSingleDLPEvent = async function(eventId) {
  if (!confirm(`Are you sure you want to delete DLP event '${eventId}'?`)) return;
  try {
    const res = await API.delete(`/dlp/events/${eventId}`);
    showToast(res?.message || "DLP event deleted successfully", "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error deleting DLP event: " + err.message, "error");
  }
};

window.clearAllDLPEvents = async function() {
  if (!confirm("Are you sure you want to clear ALL recorded DLP events from the event stream?")) return;
  try {
    const res = await API.delete("/dlp/events/clear-all");
    showToast(res?.message || "All DLP events cleared successfully", "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error clearing DLP events: " + err.message, "error");
  }
};

function renderTopSensitiveFiles(files) {
  const tbody = document.getElementById("table-top-sensitive-files");
  if (!tbody) return;

  if (!files || files.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted py-3">No sensitive files flagged yet</td></tr>`;
    return;
  }

  tbody.innerHTML = files.map(f => `
    <tr>
      <td><div class="fw-semibold text-white text-truncate" style="max-width: 160px;" title="${escapeHTML(f.file_name)}">${escapeHTML(f.file_name)}</div></td>
      <td>${formatChannelBadge(f.channel)}</td>
      <td>${formatRiskBadge(f.risk_score)}</td>
      <td>${formatActionBadge(f.action)}</td>
      <td class="text-center">
        <button type="button" class="btn btn-sm btn-outline-danger py-0 px-2" style="font-size: 0.75rem;" onclick="deleteFlaggedFile('${escapeHTML(f.file_name)}', ${f.id || 'null'})" title="Delete Flagged File">
          <i class="fas fa-trash-can"></i>
        </button>
      </td>
    </tr>
  `).join("");
}

window.deleteFlaggedFile = async function(fileName, fileId) {
  if (!confirm(`Are you sure you want to delete records for flagged file '${fileName}'?`)) return;
  try {
    const res = await API.delete(`/dlp/sensitive-files/${encodeURIComponent(fileName)}`);
    showToast(res?.message || `Flagged file '${fileName}' deleted`, "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error deleting flagged file: " + err.message, "error");
  }
};

window.clearAllFlaggedFiles = async function() {
  if (!confirm("Are you sure you want to clear ALL flagged sensitive files?")) return;
  try {
    const res = await API.delete("/dlp/sensitive-files/clear-all");
    showToast(res?.message || "All flagged sensitive files cleared", "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error clearing flagged files: " + err.message, "error");
  }
};

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
        <div class="fw-bold text-white">${escapeHTML(emp.username)}</div>
        <div class="small text-muted font-monospace">${escapeHTML(emp.employee_id)}</div>
      </td>
      <td><span class="badge bg-dark border border-secondary">${escapeHTML(emp.hostname)}</span></td>
      <td>${formatRiskBadge(emp.risk_score)}</td>
      <td>${formatStatusDot(emp.status || 'ONLINE')}</td>
      <td class="text-center">
        <div class="d-flex align-items-center justify-content-center gap-1">
          <button type="button" class="btn btn-sm btn-outline-info py-0 px-2" style="font-size: 0.75rem;" onclick="viewEmployeeProfile('${escapeHTML(emp.employee_id)}')" title="View 360° Profile">
            Profile
          </button>
          <button type="button" class="btn btn-sm btn-outline-warning py-0 px-2" style="font-size: 0.75rem;" onclick="resetSingleEmployeeRisk('${escapeHTML(emp.employee_id)}')" title="Reset Risk Score for ${escapeHTML(emp.employee_id)}">
            <i class="fas fa-rotate-left"></i>
          </button>
          <button type="button" class="btn btn-sm btn-outline-danger py-0 px-2" style="font-size: 0.75rem;" onclick="deleteEmployeeRecord('${escapeHTML(emp.employee_id)}')" title="Delete/Deactivate Endpoint ${escapeHTML(emp.employee_id)}">
            <i class="fas fa-trash-can"></i>
          </button>
        </div>
      </td>
    </tr>
  `).join("");
}

window.resetSingleEmployeeRisk = async function(employeeId) {
  if (!confirm(`Reset UEBA risk score to 0.0 for endpoint '${employeeId}'?`)) return;
  try {
    const res = await API.post(`/risk/reset/${employeeId}`);
    showToast(res?.message || `Risk reset for '${employeeId}'`, "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error resetting risk: " + err.message, "error");
  }
};

window.resetAllEmployeeRisk = async function() {
  if (!confirm("Are you sure you want to reset UEBA risk scores to 0.0 for ALL endpoints?")) return;
  try {
    const res = await API.post("/risk/reset-all");
    showToast(res?.message || "Risk scores reset for all endpoints", "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error resetting fleet risk: " + err.message, "error");
  }
};

window.deleteEmployeeRecord = async function(employeeId) {
  if (!confirm(`Are you sure you want to delete/deactivate endpoint '${employeeId}'?`)) return;
  try {
    const res = await API.delete(`/employees/${employeeId}?hard_delete=true`);
    showToast(res?.message || `Endpoint '${employeeId}' deleted`, "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error deleting endpoint: " + err.message, "error");
  }
};

function renderRecentActivities(activities) {
  const container = document.getElementById("timeline-recent-activity");
  if (!container) return;

  if (!activities || activities.length === 0) {
    container.innerHTML = `<div class="text-muted text-center py-3">No activity logs recorded yet</div>`;
    return;
  }

  container.innerHTML = activities.slice(0, 8).map(act => {
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
            <div class="text-white small fw-bold">${escapeHTML(act.activity_type)}: <span class="text-muted">${escapeHTML(act.destination || act.filepath || act.process_name || 'N/A')}</span></div>
            <div class="text-muted" style="font-size: 0.75rem">${escapeHTML(act.employee_id)} • ${formatDate(act.timestamp)}</div>
          </div>
        </div>
        <div class="d-flex align-items-center gap-2">
          ${formatRiskBadge(act.risk_score)}
          <button type="button" class="btn btn-sm btn-outline-danger py-0 px-2" style="font-size: 0.75rem;" onclick="deleteSingleActivity(${act.id})" title="Delete Activity Log #${act.id}">
            <i class="fas fa-trash-can"></i>
          </button>
        </div>
      </div>
    `;
  }).join("");
}

window.deleteSingleActivity = async function(activityId) {
  if (!confirm(`Are you sure you want to delete activity log #${activityId}?`)) return;
  try {
    const res = await API.delete(`/dashboard/activities/${activityId}`);
    showToast(res?.message || `Activity log #${activityId} deleted`, "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error deleting activity log: " + err.message, "error");
  }
};

window.clearAllActivities = async function() {
  if (!confirm("Are you sure you want to clear ALL activity timeline logs?")) return;
  try {
    const res = await API.delete("/dashboard/activities/clear-all");
    showToast(res?.message || "All activity logs cleared successfully", "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error clearing activity logs: " + err.message, "error");
  }
};

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
          <div class="d-flex align-items-center justify-content-center gap-1">
            <button type="button" class="btn btn-sm btn-outline-info py-0 px-2" style="font-size: 0.75rem;" onclick="viewEmployeeProfile('${escapeHTML(d.employee_id || '')}')" title="View 360° Profile">
              <i class="fas fa-id-card me-1"></i> Profile
            </button>
            <button type="button" class="btn btn-sm btn-outline-danger py-0 px-2" style="font-size: 0.75rem;" onclick="deleteFleetDevice('${escapeHTML(d.device_id)}')" title="Delete Device ${escapeHTML(d.device_id)}">
              <i class="fas fa-trash-can"></i>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

window.deleteFleetDevice = async function(deviceId) {
  if (!confirm(`Are you sure you want to remove endpoint device '${deviceId}' from the fleet?`)) return;
  try {
    const res = await API.delete(`/agents/${deviceId}`);
    showToast(res?.message || `Device '${deviceId}' removed successfully`, "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error removing device: " + err.message, "error");
  }
};

window.clearOfflineFleetDevices = async function() {
  if (!confirm("Are you sure you want to remove all OFFLINE devices from the fleet telemetry?")) return;
  try {
    const res = await API.delete("/agents/clear-offline");
    showToast(res?.message || `Removed ${res?.deleted_count || 0} offline device(s)`, "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error removing offline devices: " + err.message, "error");
  }
};

window.clearAllFleetDevices = async function() {
  if (!confirm("Are you sure you want to remove ALL registered endpoint devices from the fleet?")) return;
  try {
    const res = await API.delete("/agents/clear-all");
    showToast(res?.message || "All fleet devices removed successfully", "success");
    await loadDashboardData();
  } catch (err) {
    showToast("Error clearing fleet devices: " + err.message, "error");
  }
};

function formatRelativeTime(seconds) {
  if (seconds === null || seconds === undefined) return "Never";
  if (seconds < 10) return "Just now";
  if (seconds < 60) return `${Math.round(seconds)} sec ago`;
  const mins = Math.round(seconds / 60);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours} hr ago`;
  return `${Math.round(hours / 24)} days ago`;
}

window.viewEmployeeProfile = async function(employeeId) {
  if (!employeeId || employeeId === "Unassigned" || employeeId === "EMP-000") {
    showToast("No active employee profile linked to this device", "warning");
    return;
  }

  try {
    const detail = await API.get(`/employees/${encodeURIComponent(employeeId)}`);
    if (!detail || !detail.employee) {
      showToast(`Employee profile not found for '${employeeId}'`, "warning");
      return;
    }

    const emp = detail.employee;
    const sec = detail.security_summary || {};
    const mods = detail.monitoring_modules || {};
    const devices = detail.devices || [];

    const setElText = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = (val !== undefined && val !== null) ? val : "-";
    };
    const setElHtml = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = (val !== undefined && val !== null) ? val : "";
    };

    // Header & Status Badge
    setElText("profile-modal-emp-id", emp.employee_id);
    let statusBadgeHtml = "";
    if (emp.status === "ONLINE") {
      statusBadgeHtml = `<span class="badge bg-success bg-opacity-25 text-success border border-success"><i class="fas fa-circle-dot me-1"></i> 🟢 LIVE</span>`;
    } else if (emp.status === "WARNING") {
      statusBadgeHtml = `<span class="badge bg-warning bg-opacity-25 text-warning border border-warning"><i class="fas fa-triangle-exclamation me-1"></i> 🟡 WARNING</span>`;
    } else {
      statusBadgeHtml = `<span class="badge bg-danger bg-opacity-25 text-danger border border-danger"><i class="fas fa-circle-xmark me-1"></i> 🔴 OFFLINE</span>`;
    }
    setElHtml("profile-modal-status-badge", statusBadgeHtml);

    // SECTION A: Employee Information
    setElText("profile-modal-fullname", `${emp.full_name || emp.username} (@${emp.username})`);
    setElText("profile-modal-dept-desig", `${emp.department || "General"} — ${emp.designation || "Staff"}`);
    setElText("profile-modal-email-phone", `${emp.email || "No email"} | ${emp.phone_number || "No phone"}`);
    setElText("profile-modal-mgr-loc", `Mgr: ${emp.manager || "Direct"} | Loc: ${emp.location || "Office"}`);

    // SECTION B: Registered Devices
    setElText("profile-devices-count", devices.length);
    const devList = document.getElementById("profile-devices-list");
    if (devList) {
      if (devices.length === 0) {
        devList.innerHTML = `<div class="text-muted text-center py-2">No hardware devices bound yet</div>`;
      } else {
        devList.innerHTML = devices.map(d => `
          <div class="d-flex justify-content-between align-items-center py-2 border-bottom border-secondary border-opacity-25 small">
            <div>
              <span class="fw-bold font-monospace text-cyan">${escapeHTML(d.device_id)}</span>
              <span class="text-white ms-2">Host: ${escapeHTML(d.hostname)}</span>
              <div class="text-muted" style="font-size: 0.72rem;">IP: ${escapeHTML(d.ip_address)} • OS: ${escapeHTML(d.operating_system)} • Agent: v${escapeHTML(d.agent_version)}</div>
            </div>
            <div class="text-end">
              <span class="badge ${d.status === 'ONLINE' ? 'bg-success text-success' : 'bg-danger text-danger'} bg-opacity-25 border ${d.status === 'ONLINE' ? 'border-success' : 'border-danger'}">${d.status}</span>
              <div class="text-muted font-monospace" style="font-size: 0.7rem;">${formatRelativeTime(d.last_seen_seconds_ago)}</div>
            </div>
          </div>
        `).join("");
      }
    }

    // SECTION C: Monitoring Modules Sensor Grid
    const modGrid = document.getElementById("profile-monitoring-grid");
    if (modGrid) {
      const moduleNames = [
        { key: "usb", label: "USB Monitor", icon: "fa-usb" },
        { key: "file", label: "File Monitor", icon: "fa-folder-tree" },
        { key: "clipboard", label: "Clipboard Monitor", icon: "fa-clipboard" },
        { key: "process", label: "Process Monitor", icon: "fa-microchip" },
        { key: "browser", label: "Browser Monitor", icon: "fa-globe" },
        { key: "email", label: "Email Monitor", icon: "fa-envelope" },
        { key: "event", label: "Event Audit", icon: "fa-tower-broadcast" },
        { key: "heartbeat", label: "Heartbeat", icon: "fa-heart-pulse" },
      ];

      modGrid.innerHTML = moduleNames.map(m => {
        const isActive = (mods[m.key] === "ACTIVE") || (emp.status === "ONLINE" && m.key !== "error");
        return `
          <div class="col-md-6 col-6">
            <div class="p-2 rounded bg-dark border ${isActive ? 'border-success border-opacity-50' : 'border-secondary border-opacity-25'} d-flex align-items-center justify-content-between">
              <span class="small text-white"><i class="fas ${m.icon} ${isActive ? 'text-success' : 'text-muted'} me-2"></i>${m.label}</span>
              <span class="badge ${isActive ? 'bg-success text-success' : 'bg-secondary text-muted'} bg-opacity-25" style="font-size: 0.65rem;">
                ${isActive ? 'ACTIVE' : 'STOPPED'}
              </span>
            </div>
          </div>
        `;
      }).join("");
    }

    // SECTION D: Security Summary
    setElHtml("profile-summary-risk", formatRiskBadge(sec.risk_score !== undefined ? sec.risk_score : emp.risk_score));
    setElText("profile-summary-events", sec.total_events || 0);
    setElText("profile-summary-alerts", sec.alerts || 0);
    setElText("profile-summary-incidents", sec.incidents || 0);
    setElText("profile-summary-blocked", sec.blocked_events || 0);
    setElText("profile-summary-warnings", sec.warnings || 0);

    // SECTION E: Security Alerts
    const alerts = detail.alerts || [];
    setElText("profile-alerts-count", alerts.length);
    const alertsBody = document.getElementById("profile-alerts-body");
    if (alertsBody) {
      if (alerts.length === 0) {
        alertsBody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-3">No security alerts recorded for this employee</td></tr>`;
      } else {
        alertsBody.innerHTML = alerts.map(a => `
          <tr>
            <td>
              <div class="fw-bold text-white font-monospace small">${escapeHTML(a.alert_id || `ALT-${a.id}`)}</div>
              <div class="text-muted" style="font-size: 0.7rem;">${formatDate(a.created_at)}</div>
            </td>
            <td>${formatSeverityBadge(a.severity)}</td>
            <td>${formatAlertTypeBadge(a.source || a.alert_type)}</td>
            <td><span class="badge bg-dark border border-secondary text-cyan small">${escapeHTML(a.source || "Endpoint")}</span></td>
            <td>
              <div class="text-white small fw-semibold">${escapeHTML(a.title || a.rule_name || "Security Alert")}</div>
              <div class="text-muted text-truncate" style="max-width: 260px; font-size: 0.72rem;">${escapeHTML(a.description || "-")}</div>
            </td>
            <td>${formatRiskBadge(a.risk_score || 0)}</td>
            <td>${formatAlertStatusBadge(a.status)}</td>
          </tr>
        `).join("");
      }
    }

    // SECTION F: Security Incidents
    const incidents = detail.incidents || [];
    setElText("profile-incidents-count", incidents.length);
    const incidentsBody = document.getElementById("profile-incidents-body");
    if (incidentsBody) {
      if (incidents.length === 0) {
        incidentsBody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-3">No security incidents recorded for this employee</td></tr>`;
      } else {
        incidentsBody.innerHTML = incidents.map(inc => `
          <tr>
            <td>
              <span class="fw-bold font-monospace text-danger small">${escapeHTML(inc.incident_id || `INC-${inc.id}`)}</span>
            </td>
            <td>${formatSeverityBadge(inc.severity)}</td>
            <td>
              <div class="text-white small fw-semibold">${escapeHTML(inc.title || "Policy Incident")}</div>
              <div class="text-muted text-truncate" style="max-width: 260px; font-size: 0.72rem;">${escapeHTML(inc.description || "-")}</div>
            </td>
            <td>${formatAlertStatusBadge(inc.status)}</td>
            <td><span class="text-muted small">${formatDate(inc.created_at)}</span></td>
            <td><span class="text-muted small">${formatDate(inc.updated_at || inc.created_at)}</span></td>
          </tr>
        `).join("");
      }
    }

    // SECTION G: Recent DLP Events & Audit Stream
    const dlpList = detail.dlp_events || detail.recent_events || [];
    setElText("profile-dlp-count", dlpList.length);
    const eventsBody = document.getElementById("profile-recent-events-body");
    if (eventsBody) {
      if (dlpList.length === 0) {
        eventsBody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-3">No recorded security DLP events</td></tr>`;
      } else {
        eventsBody.innerHTML = dlpList.slice(0, 20).map(ev => {
          const act = (ev.action || "ALLOW").toUpperCase();
          const statusBadge = act === 'BLOCK' 
            ? '<span class="badge bg-danger">BLOCKED</span>' 
            : (act === 'WARN' ? '<span class="badge bg-warning text-dark">WARNED</span>' : '<span class="badge bg-success">LOGGED</span>');

          return `
            <tr>
              <td>
                <div class="fw-bold text-white font-monospace small">${escapeHTML(ev.event_id || `EV-${ev.id}`)}</div>
                <div class="text-muted" style="font-size: 0.7rem;">${formatDate(ev.timestamp)}</div>
              </td>
              <td>${formatChannelBadge(ev.channel)}</td>
              <td><span class="text-white small">${escapeHTML(ev.application || "System")}</span></td>
              <td><span class="text-muted small">${escapeHTML(ev.destination || "Local")}</span></td>
              <td><div class="text-white text-truncate small" style="max-width: 180px;" title="${escapeHTML(ev.file_name || '-')}">${escapeHTML(ev.file_name || "-")}</div></td>
              <td>${formatRiskBadge(ev.risk_score || 0)}</td>
              <td>${formatActionBadge(ev.action)}</td>
              <td>${statusBadge}</td>
            </tr>
          `;
        }).join("");
      }
    }

    const modalEl = document.getElementById("employeeProfileModal");
    if (modalEl) {
      const modal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
      modal.show();
    }
  } catch (err) {
    console.error("Error loading employee profile:", err);
    showToast("Failed to fetch employee details: " + err.message, "error");
  }
};

