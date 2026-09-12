// SentinelDLP Enterprise Employee Fleet & Management Controller
let allEmployees = [];
let currentFilteredEmployees = [];
let selectedEmployeeIds = new Set();
let autoRefreshTimer = null;

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
  loadEmployees();

  // Polling every 5 seconds for live status updates without page reload
  autoRefreshTimer = setInterval(loadEmployees, 5000);

  document.getElementById("filter-emp-status")?.addEventListener("change", applyEmpFilters);
  document.getElementById("filter-emp-dept")?.addEventListener("change", applyEmpFilters);
  document.getElementById("filter-emp-os")?.addEventListener("change", applyEmpFilters);
  document.getElementById("filter-emp-search")?.addEventListener("input", applyEmpFilters);

  // Check URL query params for auto-open
  const urlParams = new URLSearchParams(window.location.search);
  const empId = urlParams.get("id");
  if (empId) {
    setTimeout(() => viewEmployeeProfile(empId), 400);
  }
});

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

async function loadEmployees() {
  try {
    const data = await API.get("/employees");
    allEmployees = data || [];
    applyEmpFilters();
  } catch (err) {
    console.debug("Failed to load employees:", err.message);
  }
}

function applyEmpFilters() {
  const status = document.getElementById("filter-emp-status")?.value || "";
  const dept = document.getElementById("filter-emp-dept")?.value || "";
  const os = document.getElementById("filter-emp-os")?.value || "";
  const search = document.getElementById("filter-emp-search")?.value.toLowerCase().trim() || "";

  currentFilteredEmployees = allEmployees.filter(e => {
    if (status && e.status !== status) return false;
    if (dept && !(e.department || "").toLowerCase().includes(dept.toLowerCase())) return false;
    if (os && !(e.operating_system || "").toLowerCase().includes(os.toLowerCase())) return false;
    if (search) {
      const matchId = (e.employee_id || "").toLowerCase().includes(search);
      const matchName = (e.full_name || "").toLowerCase().includes(search);
      const matchUser = (e.username || "").toLowerCase().includes(search);
      const matchDev = (e.primary_device_id || "").toLowerCase().includes(search);
      const matchHost = (e.hostname || "").toLowerCase().includes(search);
      const matchEmail = (e.email || "").toLowerCase().includes(search);
      if (!matchId && !matchName && !matchUser && !matchDev && !matchHost && !matchEmail) return false;
    }
    return true;
  });

  renderEmployees(currentFilteredEmployees);
}

function renderEmployees(employees) {
  const tbody = document.getElementById("employees-table-body");
  if (!tbody) return;

  if (employees.length === 0) {
    tbody.innerHTML = `<tr><td colspan="14" class="text-center text-muted py-4"><i class="fas fa-users-slash me-2"></i>No matching employee endpoints registered</td></tr>`;
    updateEmployeeSelectionUI();
    return;
  }

  tbody.innerHTML = employees.map(e => {
    let statusBadge = "";
    if (e.status === "ONLINE") {
      statusBadge = `<span class="badge bg-success bg-opacity-25 text-success border border-success"><i class="fas fa-circle-dot text-success me-1"></i> LIVE</span>`;
    } else if (e.status === "WARNING") {
      statusBadge = `<span class="badge bg-warning bg-opacity-25 text-warning border border-warning"><i class="fas fa-triangle-exclamation text-warning me-1"></i> WARNING</span>`;
    } else {
      statusBadge = `<span class="badge bg-danger bg-opacity-25 text-danger border border-danger"><i class="fas fa-circle-xmark text-danger me-1"></i> OFFLINE</span>`;
    }

    const isLive = e.status === "ONLINE";
    const modBadges = `
      <div class="d-flex flex-wrap gap-1" style="font-size: 0.65rem;">
        <span class="badge ${isLive ? 'bg-success' : 'bg-secondary'} bg-opacity-25 ${isLive ? 'text-success' : 'text-muted'} border ${isLive ? 'border-success' : 'border-secondary'}">USB</span>
        <span class="badge ${isLive ? 'bg-success' : 'bg-secondary'} bg-opacity-25 ${isLive ? 'text-success' : 'text-muted'} border ${isLive ? 'border-success' : 'border-secondary'}">File</span>
        <span class="badge ${isLive ? 'bg-success' : 'bg-secondary'} bg-opacity-25 ${isLive ? 'text-success' : 'text-muted'} border ${isLive ? 'border-success' : 'border-secondary'}">Clip</span>
        <span class="badge ${isLive ? 'bg-success' : 'bg-secondary'} bg-opacity-25 ${isLive ? 'text-success' : 'text-muted'} border ${isLive ? 'border-success' : 'border-secondary'}">Proc</span>
        <span class="badge ${isLive ? 'bg-success' : 'bg-secondary'} bg-opacity-25 ${isLive ? 'text-success' : 'text-muted'} border ${isLive ? 'border-success' : 'border-secondary'}">Web</span>
        <span class="badge ${isLive ? 'bg-success' : 'bg-secondary'} bg-opacity-25 ${isLive ? 'text-success' : 'text-muted'} border ${isLive ? 'border-success' : 'border-secondary'}">Mail</span>
      </div>
    `;

    const isChecked = selectedEmployeeIds.has(e.employee_id);

    return `
      <tr>
        <td class="text-center">
          <input type="checkbox" class="form-check-input emp-select-chk bg-dark border-secondary" value="${escapeHTML(e.employee_id)}" ${isChecked ? 'checked' : ''} onchange="toggleSelectEmployee('${escapeHTML(e.employee_id)}', this.checked)">
        </td>
        <td>${statusBadge}</td>
        <td>
          <span class="fw-bold text-cyan font-monospace">${escapeHTML(e.employee_id)}</span>
        </td>
        <td>
          <div class="fw-bold text-white">${escapeHTML(e.full_name || e.username)}</div>
          <div class="text-muted" style="font-size: 0.72rem;">@${escapeHTML(e.username)}</div>
        </td>
        <td><span class="badge bg-dark border border-secondary text-white">${escapeHTML(e.department || "General")}</span></td>
        <td><span class="text-muted small">${escapeHTML(e.designation || "Staff")}</span></td>
        <td>
          <div class="text-white small">${escapeHTML(e.email || "-")}</div>
          <div class="text-muted font-monospace" style="font-size: 0.7rem;">${escapeHTML(e.phone_number || "")}</div>
        </td>
        <td>
          <div class="fw-semibold text-white">${escapeHTML(e.primary_device_id || e.hostname)}</div>
          <div class="text-muted small">${escapeHTML(e.hostname)}</div>
        </td>
        <td><span class="font-monospace text-muted small">${escapeHTML(e.ip_address || "127.0.0.1")}</span></td>
        <td><span class="text-muted small">${escapeHTML(e.operating_system || "Windows")}</span></td>
        <td><span class="badge bg-secondary bg-opacity-25 text-white">${isLive ? 'ACTIVE' : 'STOPPED'}</span></td>
        <td>${modBadges}</td>
        <td><span class="text-muted small font-monospace"><i class="fas fa-heart-pulse text-info me-1"></i>${formatRelativeTime(e.last_seen_seconds_ago)}</span></td>
        <td class="text-center">
          <div class="d-flex align-items-center justify-content-center gap-1">
            <button class="btn btn-sm btn-cyan py-0 px-2" onclick="viewEmployeeProfile('${escapeHTML(e.employee_id)}')" title="View 360° Profile">
              <i class="fas fa-id-card me-1"></i> Profile
            </button>
            <button class="btn btn-sm btn-outline-danger py-0 px-2" onclick="handleDeleteEmployee('${escapeHTML(e.employee_id)}')" title="Deactivate Employee">
              <i class="fas fa-trash-can me-1"></i> Delete
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");

  updateEmployeeSelectionUI();
}

window.toggleSelectEmployee = function(employeeId, isChecked) {
  if (isChecked) {
    selectedEmployeeIds.add(employeeId);
  } else {
    selectedEmployeeIds.delete(employeeId);
  }
  updateEmployeeSelectionUI();
};

window.toggleSelectAllEmployees = function(isChecked) {
  const visible = currentFilteredEmployees.length > 0 ? currentFilteredEmployees : allEmployees;
  if (isChecked) {
    visible.forEach(e => selectedEmployeeIds.add(e.employee_id));
  } else {
    visible.forEach(e => selectedEmployeeIds.delete(e.employee_id));
  }
  document.querySelectorAll(".emp-select-chk").forEach(chk => {
    chk.checked = isChecked;
  });
  updateEmployeeSelectionUI();
};

window.updateEmployeeSelectionUI = function() {
  const count = selectedEmployeeIds.size;
  const countSpan = document.getElementById("emp-selected-count");
  const delBtn = document.getElementById("btn-delete-selected-employees");
  if (countSpan) countSpan.textContent = count;
  if (delBtn) {
    if (count > 0) {
      delBtn.classList.remove("d-none");
    } else {
      delBtn.classList.add("d-none");
    }
  }

  const selectAll = document.getElementById("select-all-employees");
  if (selectAll) {
    const visible = currentFilteredEmployees.length > 0 ? currentFilteredEmployees : allEmployees;
    if (visible.length > 0) {
      const allSelected = visible.every(e => selectedEmployeeIds.has(e.employee_id));
      const someSelected = visible.some(e => selectedEmployeeIds.has(e.employee_id));
      selectAll.checked = allSelected;
      selectAll.indeterminate = !allSelected && someSelected;
    } else {
      selectAll.checked = false;
      selectAll.indeterminate = false;
    }
  }
};

window.deleteSelectedEmployees = async function() {
  const count = selectedEmployeeIds.size;
  if (count === 0) return;

  const confirmMsg = `Are you sure you want to deactivate ${count} selected employee(s)?`;
  if (!confirm(confirmMsg)) return;

  try {
    const payload = {
      employee_ids: Array.from(selectedEmployeeIds),
      hard_delete: false
    };
    const res = await API.post("/employees/bulk-delete", payload);
    showToast(res.message || `Successfully deactivated ${res.deleted_count} employee(s)`, "success");
    selectedEmployeeIds.clear();
    updateEmployeeSelectionUI();
    await loadEmployees();
  } catch (err) {
    showToast("Bulk delete failed: " + err.message, "error");
  }
};

window.handleCreateEmployee = async function(event) {
  event.preventDefault();
  const empId = document.getElementById("new-emp-id")?.value.trim();
  const username = document.getElementById("new-emp-username")?.value.trim();
  const fullName = document.getElementById("new-emp-fullname")?.value.trim();
  const email = document.getElementById("new-emp-email")?.value.trim() || null;
  const phone = document.getElementById("new-emp-phone")?.value.trim() || null;
  const dept = document.getElementById("new-emp-dept")?.value.trim() || "General";
  const desig = document.getElementById("new-emp-desig")?.value.trim() || "Employee";
  const mgr = document.getElementById("new-emp-manager")?.value.trim() || null;
  const loc = document.getElementById("new-emp-loc")?.value.trim() || null;

  if (!empId || !username) {
    showToast("Employee ID and Username are required", "error");
    return;
  }

  try {
    const payload = {
      employee_id: empId,
      username: username,
      full_name: fullName || username,
      email: email,
      phone_number: phone,
      department: dept,
      designation: desig,
      manager: mgr,
      location: loc
    };
    await API.post("/employees", payload);
    showToast(`Employee ${empId} registered successfully`, "success");
    
    // Close modal & reset form
    const modalEl = document.getElementById("createEmployeeModal");
    const modal = bootstrap.Modal.getInstance(modalEl);
    if (modal) modal.hide();
    document.getElementById("create-employee-form")?.reset();

    await loadEmployees();
  } catch (err) {
    showToast("Failed to create employee: " + err.message, "error");
  }
};

window.handleDeleteEmployee = async function(employeeId) {
  if (!confirm(`Are you sure you want to deactivate employee '${employeeId}'?`)) return;
  try {
    await API.delete(`/employees/${employeeId}`);
    showToast(`Employee '${employeeId}' deactivated`, "success");
    await loadEmployees();
  } catch (err) {
    showToast("Error deactivating employee: " + err.message, "error");
  }
};

window.viewEmployeeProfile = async function(employeeId) {
  try {
    const detail = await API.get(`/employees/${employeeId}`);
    const emp = detail.employee;
    const sec = detail.security_summary || {};
    const mods = detail.monitoring_modules || {};
    const devices = detail.devices || [];

    // Header & Status Badge
    document.getElementById("profile-modal-emp-id").textContent = emp.employee_id;
    let statusBadgeHtml = "";
    if (emp.status === "ONLINE") {
      statusBadgeHtml = `<span class="badge bg-success bg-opacity-25 text-success border border-success"><i class="fas fa-circle-dot me-1"></i> 🟢 LIVE</span>`;
    } else if (emp.status === "WARNING") {
      statusBadgeHtml = `<span class="badge bg-warning bg-opacity-25 text-warning border border-warning"><i class="fas fa-triangle-exclamation me-1"></i> 🟡 WARNING</span>`;
    } else {
      statusBadgeHtml = `<span class="badge bg-danger bg-opacity-25 text-danger border border-danger"><i class="fas fa-circle-xmark me-1"></i> 🔴 OFFLINE</span>`;
    }
    document.getElementById("profile-modal-status-badge").innerHTML = statusBadgeHtml;

    // SECTION A: Employee Information
    document.getElementById("profile-modal-fullname").textContent = `${emp.full_name || emp.username} (@${emp.username})`;
    document.getElementById("profile-modal-dept-desig").textContent = `${emp.department || "General"} — ${emp.designation || "Staff"}`;
    document.getElementById("profile-modal-email-phone").textContent = `${emp.email || "No email"} | ${emp.phone_number || "No phone"}`;
    document.getElementById("profile-modal-mgr-loc").textContent = `Mgr: ${emp.manager || "Direct"} | Loc: ${emp.location || "Office"}`;

    // SECTION B: Registered Devices
    document.getElementById("profile-devices-count").textContent = devices.length;
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
    document.getElementById("profile-summary-risk").innerHTML = formatRiskBadge(sec.risk_score || emp.risk_score);
    document.getElementById("profile-summary-events").textContent = sec.total_events || 0;
    document.getElementById("profile-summary-alerts").textContent = sec.alerts || 0;
    document.getElementById("profile-summary-incidents").textContent = sec.incidents || 0;
    document.getElementById("profile-summary-blocked").textContent = sec.blocked_events || 0;
    document.getElementById("profile-summary-warnings").textContent = sec.warnings || 0;

    // SECTION E: Recent Activity & DLP Events
    const eventsBody = document.getElementById("profile-recent-events-body");
    if (eventsBody) {
      const dlpList = detail.dlp_events || [];
      const actList = detail.activities || [];

      if (dlpList.length === 0 && actList.length === 0) {
        eventsBody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-3">No recorded security or activity events</td></tr>`;
      } else {
        const rows = [];
        for (const ev of dlpList.slice(0, 10)) {
          rows.push(`
            <tr>
              <td><span class="text-muted small">${formatDate(ev.timestamp)}</span></td>
              <td><span class="badge bg-dark border border-secondary text-cyan">${ev.channel}</span></td>
              <td><div class="text-white text-truncate small" style="max-width: 180px;">${escapeHTML(ev.file_name || ev.application)}</div></td>
              <td><span class="text-muted small">${escapeHTML(ev.destination || "Local")}</span></td>
              <td>${formatSeverityBadge(ev.risk_level)}</td>
              <td>${formatActionBadge(ev.action)}</td>
            </tr>
          `);
        }
        for (const act of actList.slice(0, 10)) {
          rows.push(`
            <tr>
              <td><span class="text-muted small">${formatDate(act.timestamp)}</span></td>
              <td><span class="badge bg-secondary bg-opacity-25 text-white">${act.activity_type}</span></td>
              <td><div class="text-white text-truncate small" style="max-width: 180px;">${escapeHTML(act.filepath || act.process_name || 'System')}</div></td>
              <td><span class="text-muted small">${escapeHTML(act.destination || "Local")}</span></td>
              <td>${formatRiskBadge(act.risk_score)}</td>
              <td><span class="badge bg-secondary text-white">AUDIT</span></td>
            </tr>
          `);
        }
        eventsBody.innerHTML = rows.slice(0, 15).join("");
      }
    }

    const modal = new bootstrap.Modal(document.getElementById("employeeProfileModal"));
    modal.show();
  } catch (err) {
    showToast("Failed to fetch employee details: " + err.message, "error");
  }
};
