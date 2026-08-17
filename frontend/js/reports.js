// Compliance & Security Reports Controller
document.addEventListener("DOMContentLoaded", () => {
  loadExecutiveReport();

  document.getElementById("btn-export-alerts-csv")?.addEventListener("click", exportAlertsCSV);
  document.getElementById("btn-export-activities-csv")?.addEventListener("click", exportActivitiesCSV);
});

async function loadExecutiveReport() {
  try {
    const data = await API.get("/reports/summary");
    renderExecutiveSummary(data);
  } catch (err) {
    showToast("Failed to generate executive report: " + err.message, "error");
  }
}

function renderExecutiveSummary(report) {
  const m = report.metrics;
  document.getElementById("rep-endpoints").textContent = m.total_endpoints;
  document.getElementById("rep-files").textContent = m.monitored_files;
  document.getElementById("rep-sensitive").textContent = m.sensitive_files_detected;
  document.getElementById("rep-alerts").textContent = m.total_dlp_alerts;
  document.getElementById("rep-critical-alerts").textContent = m.critical_alerts;
  document.getElementById("rep-incidents").textContent = m.total_incidents;
  document.getElementById("rep-usb").textContent = m.usb_transfers_recorded;
  document.getElementById("rep-avg-risk").textContent = m.fleet_average_risk_score;
  document.getElementById("rep-timestamp").textContent = formatDate(report.generated_at);

  // Top Risk Endpoints
  const tbodyRisk = document.getElementById("rep-top-risk-body");
  if (tbodyRisk) {
    tbodyRisk.innerHTML = report.top_risk_endpoints.map(e => `
      <tr>
        <td class="text-info fw-bold">${e.employee_id}</td>
        <td class="text-white">${e.username}</td>
        <td><span class="badge bg-secondary">${e.hostname}</span></td>
        <td>${formatRiskBadge(e.risk_score)}</td>
        <td>${formatStatusDot(e.status)}</td>
      </tr>
    `).join("");
  }

  // Critical Threats
  const tbodyThreats = document.getElementById("rep-critical-threats-body");
  if (tbodyThreats) {
    tbodyThreats.innerHTML = report.recent_critical_threats.map(t => `
      <tr>
        <td class="text-muted small">${formatDate(t.created_at)}</td>
        <td class="text-info fw-semibold">${t.employee_id}</td>
        <td class="text-white">${t.alert_type}</td>
        <td class="text-muted small">${t.description}</td>
        <td>${formatRiskBadge(t.risk_score)}</td>
      </tr>
    `).join("");
  }
}

async function exportAlertsCSV() {
  try {
    const csvData = await API.get("/reports/export/alerts.csv");
    downloadFile(csvData, "sentineldlp_alerts_export.csv", "text/csv");
    showToast("Alerts CSV exported successfully", "success");
  } catch (err) {
    showToast("Export failed: " + err.message, "error");
  }
}

async function exportActivitiesCSV() {
  try {
    const csvData = await API.get("/reports/export/activities.csv");
    downloadFile(csvData, "sentineldlp_activities_export.csv", "text/csv");
    showToast("Activities CSV exported successfully", "success");
  } catch (err) {
    showToast("Export failed: " + err.message, "error");
  }
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
