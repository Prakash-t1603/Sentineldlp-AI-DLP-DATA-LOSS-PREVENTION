// File DLP Inspection Controller
let allFiles = [];
let currentFilteredFiles = [];
let selectedFileIds = new Set();

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
  loadFiles();

  document.getElementById("filter-file-class")?.addEventListener("change", applyFileFilters);
  document.getElementById("filter-file-search")?.addEventListener("input", applyFileFilters);
  document.getElementById("form-manual-scan")?.addEventListener("submit", handleManualScan);
  document.getElementById("form-upload-scan")?.addEventListener("submit", handleUploadScan);
});

async function loadFiles() {
  try {
    const data = await API.get("/files");
    allFiles = data || [];
    applyFileFilters();
  } catch (err) {
    showToast("Failed to load file records: " + err.message, "error");
  }
}

function applyFileFilters() {
  const cls = document.getElementById("filter-file-class")?.value || "";
  const search = document.getElementById("filter-file-search")?.value.toLowerCase().trim() || "";

  currentFilteredFiles = allFiles.filter(f => {
    if (cls && f.classification !== cls) return false;
    if (search) {
      const matchName = (f.filename || "").toLowerCase().includes(search);
      const matchPath = (f.filepath || "").toLowerCase().includes(search);
      const matchEmp = (f.employee_id || "").toLowerCase().includes(search);
      if (!matchName && !matchPath && !matchEmp) return false;
    }
    return true;
  });

  renderFiles(currentFilteredFiles);
}

function renderFiles(files) {
  const tbody = document.getElementById("files-table-body");
  if (!tbody) return;

  if (files.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4"><i class="fas fa-folder-open me-2"></i>No monitored file records found</td></tr>`;
    updateFileSelectionUI();
    return;
  }

  tbody.innerHTML = files.map(f => {
    const isChecked = selectedFileIds.has(f.id);
    return `
      <tr>
        <td class="text-center">
          <input type="checkbox" class="form-check-input file-select-chk bg-dark border-secondary" value="${f.id}" ${isChecked ? 'checked' : ''} onchange="toggleSelectFile(${f.id}, this.checked)">
        </td>
        <td>
          <div class="text-white fw-bold"><i class="fas fa-file me-2 text-info"></i>${escapeHTML(f.filename)}</div>
          <div class="small text-muted text-truncate font-monospace" style="max-width: 250px;">${escapeHTML(f.filepath)}</div>
        </td>
        <td><span class="text-info font-monospace">${escapeHTML(f.employee_id)}</span></td>
        <td><span class="badge bg-secondary font-monospace">${escapeHTML(f.extension)}</span></td>
        <td>${formatClassificationTag(f.classification)}</td>
        <td>
          <div class="d-flex align-items-center gap-2">
            <div class="progress flex-grow-1" style="height: 6px; width: 60px; background: rgba(255,255,255,0.1);">
              <div class="progress-bar ${f.sensitivity >= 70 ? 'bg-danger' : f.sensitivity >= 40 ? 'bg-warning' : 'bg-info'}" style="width: ${f.sensitivity}%"></div>
            </div>
            <span class="small fw-bold">${f.sensitivity}</span>
          </div>
        </td>
        <td class="text-muted small">${formatDate(f.modified_at || f.created_at)}</td>
        <td class="text-center">
          <div class="d-flex align-items-center justify-content-center gap-1">
            <button class="btn btn-sm btn-outline-info py-0 px-2" onclick="viewFileDetails(${f.id})" title="Inspect File">
              <i class="fas fa-microscope me-1"></i> Inspect
            </button>
            <button class="btn btn-sm btn-outline-danger py-0 px-2" onclick="deleteSingleFile(${f.id})" title="Delete Record">
              <i class="fas fa-trash-can me-1"></i> Delete
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");

  updateFileSelectionUI();
}

window.toggleSelectFile = function(fileId, isChecked) {
  if (isChecked) {
    selectedFileIds.add(fileId);
  } else {
    selectedFileIds.delete(fileId);
  }
  updateFileSelectionUI();
};

window.toggleSelectAllFiles = function(isChecked) {
  const visible = currentFilteredFiles.length > 0 ? currentFilteredFiles : allFiles;
  if (isChecked) {
    visible.forEach(f => selectedFileIds.add(f.id));
  } else {
    visible.forEach(f => selectedFileIds.delete(f.id));
  }
  document.querySelectorAll(".file-select-chk").forEach(chk => {
    chk.checked = isChecked;
  });
  updateFileSelectionUI();
};

window.updateFileSelectionUI = function() {
  const count = selectedFileIds.size;
  const countSpan = document.getElementById("files-selected-count");
  const delBtn = document.getElementById("btn-delete-selected-files");
  if (countSpan) countSpan.textContent = count;
  if (delBtn) {
    if (count > 0) {
      delBtn.classList.remove("d-none");
    } else {
      delBtn.classList.add("d-none");
    }
  }

  const selectAll = document.getElementById("select-all-files");
  if (selectAll) {
    const visible = currentFilteredFiles.length > 0 ? currentFilteredFiles : allFiles;
    if (visible.length > 0) {
      const allSelected = visible.every(f => selectedFileIds.has(f.id));
      const someSelected = visible.some(f => selectedFileIds.has(f.id));
      selectAll.checked = allSelected;
      selectAll.indeterminate = !allSelected && someSelected;
    } else {
      selectAll.checked = false;
      selectAll.indeterminate = false;
    }
  }
};

window.deleteSelectedFiles = async function() {
  const count = selectedFileIds.size;
  if (count === 0) return;

  const confirmMsg = `Are you sure you want to delete ${count} selected file record(s)?`;
  if (!confirm(confirmMsg)) return;

  try {
    const payload = {
      file_ids: Array.from(selectedFileIds)
    };
    const res = await API.post("/files/bulk-delete", payload);
    showToast(res.message || `Successfully deleted ${res.deleted_count} file record(s)`, "success");
    selectedFileIds.clear();
    updateFileSelectionUI();
    await loadFiles();
  } catch (err) {
    showToast("Bulk delete failed: " + err.message, "error");
  }
};

window.deleteSingleFile = async function(fileId) {
  if (!confirm(`Are you sure you want to delete file record #${fileId}?`)) return;

  try {
    await API.delete(`/files/${fileId}`);
    showToast(`File record #${fileId} deleted`, "success");
    selectedFileIds.delete(fileId);
    updateFileSelectionUI();
    await loadFiles();
  } catch (err) {
    showToast("Failed to delete file record: " + err.message, "error");
  }
};

async function handleManualScan(e) {
  e.preventDefault();
  const filepath = document.getElementById("scan-filepath").value.trim();
  const employee_id = document.getElementById("scan-emp-id").value.trim();
  const scanBtn = document.getElementById("btn-run-manual-scan");

  scanBtn.disabled = true;
  scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Analyzing File...';

  try {
    const result = await API.post("/files/scan", { filepath, employee_id });
    showToast(`Scan complete: ${result.classification} (Risk Score: ${result.risk_score})`, result.alert_created ? "warning" : "success");
    bootstrap.Modal.getInstance(document.getElementById("manualScanModal")).hide();
    document.getElementById("form-manual-scan").reset();
    loadFiles();
    showScanResultModal(result);
  } catch (err) {
    showToast("Scan failed: " + err.message, "error");
  } finally {
    scanBtn.disabled = false;
    scanBtn.innerHTML = '<i class="fas fa-search me-1"></i> Start Deep Inspection';
  }
}

async function handleUploadScan(e) {
  e.preventDefault();
  const fileInput = document.getElementById("upload-file-input");
  const empId = document.getElementById("upload-emp-id").value.trim();
  const uploadBtn = document.getElementById("btn-run-upload-scan");

  if (!fileInput.files || fileInput.files.length === 0) {
    showToast("Please choose a file to inspect", "warning");
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);
  formData.append("employee_id", empId);

  uploadBtn.disabled = true;
  uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Uploading & Classifying...';

  try {
    const result = await API.post("/files/upload-scan", formData);
    showToast(`File uploaded & classified: ${result.classification}`, result.alert_created ? "warning" : "success");
    bootstrap.Modal.getInstance(document.getElementById("uploadScanModal")).hide();
    document.getElementById("form-upload-scan").reset();
    loadFiles();
    showScanResultModal(result);
  } catch (err) {
    showToast("Upload scan failed: " + err.message, "error");
  } finally {
    uploadBtn.disabled = false;
    uploadBtn.innerHTML = '<i class="fas fa-upload me-1"></i> Upload & Classify';
  }
}

function showScanResultModal(res) {
  if (!res) return;
  const setElText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  const setElHtml = (id, val) => { const el = document.getElementById(id); if (el) el.innerHTML = val; };

  setElText("res-filename", res.filename || "N/A");
  setElHtml("res-classification", formatClassificationTag(res.classification));
  setElText("res-sensitivity", `${res.sensitivity_score || 0} / 100`);
  setElText("res-confidence", `${Math.round((res.confidence || 0) * 100)}%`);
  setElHtml("res-risk", formatRiskBadge(res.risk_score || 0));

  const entitiesList = document.getElementById("res-entities-list");
  if (entitiesList) {
    if (!res.detected_entities || res.detected_entities.length === 0) {
      entitiesList.innerHTML = `<li class="list-group-item bg-transparent text-muted">No sensitive entity patterns detected.</li>`;
    } else {
      entitiesList.innerHTML = res.detected_entities.map(e => `
        <li class="list-group-item bg-dark border-secondary text-white d-flex justify-content-between align-items-center">
          <div>
            <span class="badge bg-danger me-2">${e.entity_type}</span>
            <span class="small">${e.count} match(es)</span>
          </div>
          <div>${formatClassificationTag(e.classification)}</div>
        </li>
      `).join("");
    }
  }

  const modalEl = document.getElementById("scanResultModal");
  if (modalEl) {
    const modal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
    modal.show();
  }
}

window.viewFileDetails = function(fileId) {
  const f = allFiles.find(item => item.id === fileId);
  if (!f) return;

  showScanResultModal({
    filename: f.filename,
    filepath: f.filepath,
    classification: f.classification,
    sensitivity_score: f.sensitivity,
    confidence: 0.90,
    risk_score: f.sensitivity,
    detected_entities: []
  });
};
