// Employee Endpoint Fleet Controller
let allEmployees = [];

document.addEventListener("DOMContentLoaded", () => {
  loadEmployees();

  document.getElementById("filter-emp-status")?.addEventListener("change", applyEmpFilters);
  document.getElementById("filter-emp-search")?.addEventListener("input", applyEmpFilters);

  // Check URL query params for auto-open
  const urlParams = new URLSearchParams(window.location.search);
  const empId = urlParams.get("id");
  if (empId) {
    setTimeout(() => viewEmployeeProfile(empId), 500);
  }
});

async function loadEmployees() {
  try {
    const data = await API.get("/employees");
    allEmployees = data || [];
    renderEmployees(allEmployees);
  } catch (err) {
    showToast("Failed to load employees: " + err.message, "error");
  }
}

function applyEmpFilters() {
  const status = document.getElementById("filter-emp-status")?.value || "";
  const search = document.getElementById("filter-emp-search")?.value.toLowerCase().trim() || "";

  const filtered = allEmployees.filter(e => {
    if (status && e.status !== status) return false;
    if (search) {
      const matchId = e.employee_id.toLowerCase().includes(search);
      const matchUser = e.username.toLowerCase().includes(search);
      const matchHost = e.hostname.toLowerCase().includes(search);
      if (!matchId && !matchUser && !matchHost) return false;
    }
    return true;
  });

  renderEmployees(filtered);
}

function renderEmployees(employees) {
  const tbody = document.getElementById("employees-table-body");
  if (!tbody) return;

  if (employees.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4">No endpoint devices registered</td></tr>`;
    return;
  }

  tbody.innerHTML = employees.map(e => `
    <tr>
      <td>
        <span class="text-info fw-bold">${e.employee_id}</span>
      </td>
      <td>
        <span class="text-white fw-semibold">${e.username}</span>
      </td>
      <td><span class="badge bg-dark border border-secondary">${e.hostname}</span></td>
      <td><span class="text-muted small">${e.ip_address}</span></td>
      <td><span class="text-muted small">${e.operating_system}</span></td>
      <td>${formatStatusDot(e.status)}</td>
      <td>${formatRiskBadge(e.risk_score)}</td>
      <td>
        <button class="btn btn-sm btn-cyan" onclick="viewEmployeeProfile('${e.employee_id}')">
          <i class="fas fa-id-card me-1"></i> 360° Profile
        </button>
      </td>
    </tr>
  `).join("");
}

window.viewEmployeeProfile = async function(employeeId) {
  try {
    const detail = await API.get(`/employees/${employeeId}`);
    const emp = detail.employee;

    document.getElementById("profile-modal-emp-id").textContent = emp.employee_id;
    document.getElementById("profile-modal-user").textContent = emp.username;
    document.getElementById("profile-modal-host").textContent = emp.hostname;
    document.getElementById("profile-modal-ip").textContent = emp.ip_address;
    document.getElementById("profile-modal-os").textContent = emp.operating_system;
    document.getElementById("profile-modal-status").innerHTML = formatStatusDot(emp.status);
    document.getElementById("profile-modal-risk").innerHTML = formatRiskBadge(emp.risk_score);
    document.getElementById("profile-modal-last-seen").textContent = formatDate(emp.last_seen);

    // Render Recent Activities
    const actBody = document.getElementById("profile-activities-list");
    if (actBody) {
      if (detail.activities.length === 0) {
        actBody.innerHTML = `<div class="text-muted text-center py-2">No recorded activities</div>`;
      } else {
        actBody.innerHTML = detail.activities.slice(0, 10).map(a => `
          <div class="d-flex justify-content-between align-items-center py-1 border-bottom border-secondary border-opacity-25 small">
            <div>
              <span class="badge bg-secondary">${a.activity_type}</span>
              <span class="text-white ms-2">${a.filepath || a.process_name || 'System'}</span>
            </div>
            <div class="text-muted">${formatDate(a.timestamp)}</div>
          </div>
        `).join("");
      }
    }

    // Render Sensitive Files
    const filesBody = document.getElementById("profile-files-list");
    if (filesBody) {
      if (detail.files.length === 0) {
        filesBody.innerHTML = `<div class="text-muted text-center py-2">No sensitive files indexed</div>`;
      } else {
        filesBody.innerHTML = detail.files.slice(0, 10).map(f => `
          <div class="d-flex justify-content-between align-items-center py-1 border-bottom border-secondary border-opacity-25 small">
            <div>
              <i class="fas fa-file-alt text-info me-1"></i>
              <span class="text-white">${f.filename}</span>
            </div>
            <div>
              ${formatClassificationTag(f.classification)}
            </div>
          </div>
        `).join("");
      }
    }

    // Render Alerts
    const alertsBody = document.getElementById("profile-alerts-list");
    if (alertsBody) {
      if (detail.alerts.length === 0) {
        alertsBody.innerHTML = `<div class="text-muted text-center py-2">No threat alerts</div>`;
      } else {
        alertsBody.innerHTML = detail.alerts.slice(0, 10).map(a => `
          <div class="d-flex justify-content-between align-items-center py-1 border-bottom border-secondary border-opacity-25 small">
            <div>
              ${formatSeverityBadge(a.severity)}
              <span class="text-white ms-2">${a.alert_type}</span>
            </div>
            <div class="text-muted">${formatDate(a.created_at)}</div>
          </div>
        `).join("");
      }
    }

    const modal = new bootstrap.Modal(document.getElementById("employeeProfileModal"));
    modal.show();
  } catch (err) {
    showToast("Failed to fetch employee details: " + err.message, "error");
  }
};
