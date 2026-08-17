// Incident Response Controller
let allIncidents = [];

document.addEventListener("DOMContentLoaded", () => {
  loadIncidents();

  document.getElementById("filter-inc-status")?.addEventListener("change", applyIncFilters);
  document.getElementById("filter-inc-sev")?.addEventListener("change", applyIncFilters);
  document.getElementById("form-create-incident")?.addEventListener("submit", createNewIncident);
});

async function loadIncidents() {
  try {
    const data = await API.get("/incidents");
    allIncidents = data || [];
    renderIncidents(allIncidents);
  } catch (err) {
    showToast("Failed to load incidents: " + err.message, "error");
  }
}

function applyIncFilters() {
  const status = document.getElementById("filter-inc-status")?.value || "";
  const sev = document.getElementById("filter-inc-sev")?.value || "";

  const filtered = allIncidents.filter(i => {
    if (status && i.status !== status) return false;
    if (sev && i.severity !== sev) return false;
    return true;
  });

  renderIncidents(filtered);
}

function renderIncidents(incidents) {
  const tbody = document.getElementById("incidents-table-body");
  if (!tbody) return;

  if (incidents.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">No security incidents recorded</td></tr>`;
    return;
  }

  tbody.innerHTML = incidents.map(inc => `
    <tr>
      <td class="text-muted small">${formatDate(inc.created_at)}</td>
      <td><span class="text-info fw-bold">${inc.employee_id}</span></td>
      <td>
        <div class="text-white fw-bold">${inc.title}</div>
        <div class="small text-muted text-truncate" style="max-width: 300px;">${inc.description}</div>
      </td>
      <td>${formatSeverityBadge(inc.severity)}</td>
      <td>
        <span class="badge ${inc.status === 'RESOLVED' ? 'bg-success' : inc.status === 'CONTAINED' ? 'bg-info text-dark' : inc.status === 'INVESTIGATING' ? 'bg-primary' : 'bg-danger'}">
          ${inc.status}
        </span>
      </td>
      <td><span class="text-white small">${inc.assigned_to || 'Unassigned'}</span></td>
      <td>
        <button class="btn btn-sm btn-outline-info" onclick="viewIncidentDetail(${inc.id})">
          <i class="fas fa-edit me-1"></i> Investigate
        </button>
      </td>
    </tr>
  `).join("");
}

async function createNewIncident(e) {
  e.preventDefault();
  const empId = document.getElementById("new-inc-emp").value.trim();
  const title = document.getElementById("new-inc-title").value.trim();
  const severity = document.getElementById("new-inc-sev").value;
  const desc = document.getElementById("new-inc-desc").value.trim();

  try {
    await API.post("/incidents", {
      employee_id: empId,
      title: title,
      description: desc,
      severity: severity,
      status: "OPEN"
    });
    showToast("New security incident created!", "success");
    bootstrap.Modal.getInstance(document.getElementById("createIncidentModal")).hide();
    document.getElementById("form-create-incident").reset();
    loadIncidents();
  } catch (err) {
    showToast("Failed to create incident: " + err.message, "error");
  }
}

window.viewIncidentDetail = function(incId) {
  const inc = allIncidents.find(i => i.id === incId);
  if (!inc) return;

  document.getElementById("modal-inc-id").textContent = `#${inc.id}`;
  document.getElementById("modal-inc-title").textContent = inc.title;
  document.getElementById("modal-inc-emp").textContent = inc.employee_id;
  document.getElementById("modal-inc-desc").textContent = inc.description;
  document.getElementById("modal-inc-sev").innerHTML = formatSeverityBadge(inc.severity);
  document.getElementById("modal-inc-status").value = inc.status;
  document.getElementById("modal-inc-assignee").value = inc.assigned_to || "";
  document.getElementById("modal-inc-notes").value = inc.investigation_notes || "";

  const saveBtn = document.getElementById("btn-save-incident");
  if (saveBtn) {
    saveBtn.onclick = async () => {
      const status = document.getElementById("modal-inc-status").value;
      const assigned_to = document.getElementById("modal-inc-assignee").value.trim();
      const investigation_notes = document.getElementById("modal-inc-notes").value.trim();

      try {
        await API.patch(`/incidents/${inc.id}`, { status, assigned_to, investigation_notes });
        showToast(`Incident #${inc.id} updated!`, "success");
        bootstrap.Modal.getInstance(document.getElementById("incidentDetailModal")).hide();
        loadIncidents();
      } catch (err) {
        showToast("Failed to update incident: " + err.message, "error");
      }
    };
  }

  const modal = new bootstrap.Modal(document.getElementById("incidentDetailModal"));
  modal.show();
};
