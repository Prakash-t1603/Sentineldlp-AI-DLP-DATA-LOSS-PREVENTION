// SOC Dashboard Controller
let riskChart = null;
let alertChart = null;
let fileChart = null;

document.addEventListener("DOMContentLoaded", () => {
  loadDashboardData();

  // Refresh dashboard every 4 seconds for real-time live telemetry
  setInterval(loadDashboardData, 4000);
});

async function loadDashboardData() {
  try {
    const data = await API.get("/dashboard/summary");
    renderKPIs(data.stats);
    renderCharts(data);
    renderTopEmployees(data.top_risk_employees);
    renderRecentAlerts(data.recent_alerts);
    renderRecentActivities(data.recent_activities);
  } catch (err) {
    console.debug("Dashboard data load tick:", err.message);
  }
}

function renderKPIs(stats) {
  if (!stats) return;
  document.getElementById("kpi-total-employees").textContent = stats.total_employees;
  document.getElementById("kpi-online-employees").textContent = stats.online_employees;
  document.getElementById("kpi-sensitive-files").textContent = stats.sensitive_files;
  document.getElementById("kpi-open-alerts").textContent = stats.open_alerts;
  document.getElementById("kpi-critical-alerts").textContent = stats.critical_alerts;
  document.getElementById("kpi-active-incidents").textContent = stats.active_incidents;
  document.getElementById("kpi-avg-risk").textContent = stats.average_risk_score;
}

function renderCharts(data) {
  // 1. Risk Distribution Chart
  const riskLabels = data.risk_distribution.map(d => d.label);
  const riskCounts = data.risk_distribution.map(d => d.count);
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
          backgroundColor: riskCounts.every(c => c === 0) ? ["#374151"] : riskColors,
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#9ca3af", boxWidth: 12 } }
        },
        cutout: "70%"
      }
    });
  }

  // 2. Alerts by Severity Chart
  const alertLabels = data.alerts_by_severity.map(d => d.label);
  const alertCounts = data.alerts_by_severity.map(d => d.count);
  const alertColors = ["#10b981", "#f59e0b", "#f97316", "#ef4444"];

  const ctxAlert = document.getElementById("chart-alerts-sev")?.getContext("2d");
  if (ctxAlert) {
    if (alertChart) alertChart.destroy();
    alertChart = new Chart(ctxAlert, {
      type: "bar",
      data: {
        labels: alertLabels,
        datasets: [{
          label: "Alerts Count",
          data: alertCounts,
          backgroundColor: alertColors,
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: { ticks: { color: "#9ca3af" }, grid: { display: false } },
          y: { ticks: { color: "#9ca3af", stepSize: 1 }, grid: { color: "rgba(255, 255, 255, 0.05)" } }
        }
      }
    });
  }

  // 3. File Classification Chart
  const fileLabels = data.files_by_classification.map(d => d.label.replace("_", " "));
  const fileCounts = data.files_by_classification.map(d => d.count);
  const fileColors = ["#6b7280", "#3b82f6", "#f59e0b", "#ef4444"];

  const ctxFile = document.getElementById("chart-files-class")?.getContext("2d");
  if (ctxFile) {
    if (fileChart) fileChart.destroy();
    fileChart = new Chart(ctxFile, {
      type: "pie",
      data: {
        labels: fileLabels,
        datasets: [{
          data: fileCounts.every(c => c === 0) ? [1] : fileCounts,
          backgroundColor: fileCounts.every(c => c === 0) ? ["#374151"] : fileColors,
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#9ca3af", boxWidth: 12 } }
        }
      }
    });
  }
}

function renderTopEmployees(employees) {
  const tbody = document.getElementById("table-top-employees");
  if (!tbody) return;

  if (!employees || employees.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted py-4">No endpoint devices registered yet</td></tr>`;
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
      <td><span class="badge bg-danger bg-opacity-25 text-danger border border-danger">${emp.alert_count} Alerts</span></td>
      <td>
        <a href="/employees?id=${emp.employee_id}" class="btn btn-sm btn-outline-info">
          <i class="fas fa-eye me-1"></i> Profile
        </a>
      </td>
    </tr>
  `).join("");
}

function renderRecentAlerts(alerts) {
  const tbody = document.getElementById("table-recent-alerts");
  if (!tbody) return;

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-4">No threat alerts detected yet</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td><span class="text-muted small">${formatDate(a.created_at)}</span></td>
      <td><span class="fw-semibold text-info">${a.employee_id}</span></td>
      <td>${formatAlertTypeBadge(a.alert_type)}</td>
      <td>${formatSeverityBadge(a.severity)}</td>
      <td>${formatRiskBadge(a.risk_score)}</td>
      <td>
        <span class="badge ${a.status === 'RESOLVED' ? 'bg-success' : 'bg-warning text-dark'}">${a.status}</span>
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

  container.innerHTML = activities.slice(0, 8).map(act => {
    let icon = "fa-file-alt text-info";
    const actType = act.activity_type || "";
    if (actType.includes("USB")) icon = "fa-usb text-danger";
    else if (actType.includes("MESSAGING") || actType.includes("WHATSAPP")) icon = "fa-brands fa-whatsapp text-success";
    else if (actType.includes("WEB_STORAGE") || actType.includes("CLOUD")) icon = "fa-cloud-arrow-up text-primary";
    else if (actType.includes("EMAIL")) icon = "fa-envelope text-info";
    else if (actType.includes("CLIPBOARD")) icon = "fa-clipboard text-warning";
    else if (actType === "DELETE") icon = "fa-trash text-danger";
    else if (actType === "PROCESS_SPAWN") icon = "fa-terminal text-danger";

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

