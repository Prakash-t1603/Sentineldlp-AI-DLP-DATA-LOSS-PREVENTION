// File DLP Inspection Controller
let allFiles = [];

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
    renderFiles(allFiles);
  } catch (err) {
    showToast("Failed to load file records: " + err.message, "error");
  }
}

function applyFileFilters() {
  const cls = document.getElementById("filter-file-class")?.value || "";
  const search = document.getElementById("filter-file-search")?.value.toLowerCase().trim() || "";

  const filtered = allFiles.filter(f => {
    if (cls && f.classification !== cls) return false;
    if (search) {
      const matchName = f.filename.toLowerCase().includes(search);
      const matchPath = f.filepath.toLowerCase().includes(search);
      const matchEmp = f.employee_id.toLowerCase().includes(search);
      if (!matchName && !matchPath && !matchEmp) return false;
    }
    return true;
  });

  renderFiles(filtered);
}

function renderFiles(files) {
  const tbody = document.getElementById("files-table-body");
  if (!tbody) return;

  if (files.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">No monitored file records found</td></tr>`;
    return;
  }

  tbody.innerHTML = files.map(f => `
    <tr>
      <td>
        <div class="text-white fw-bold"><i class="fas fa-file me-2 text-info"></i>${f.filename}</div>
        <div class="small text-muted text-truncate font-monospace" style="max-width: 250px;">${f.filepath}</div>
      </td>
      <td><span class="text-info">${f.employee_id}</span></td>
      <td><span class="badge bg-secondary font-monospace">${f.extension}</span></td>
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
      <td>
        <button class="btn btn-sm btn-outline-info" onclick="viewFileDetails(${f.id})">
          <i class="fas fa-microscope me-1"></i> Inspect
        </button>
      </td>
    </tr>
  `).join("");
}

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
  document.getElementById("res-filename").textContent = res.filename;
  document.getElementById("res-classification").innerHTML = formatClassificationTag(res.classification);
  document.getElementById("res-sensitivity").textContent = `${res.sensitivity_score} / 100`;
  document.getElementById("res-confidence").textContent = `${Math.round(res.confidence * 100)}%`;
  document.getElementById("res-risk").innerHTML = formatRiskBadge(res.risk_score);

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

  const modal = new bootstrap.Modal(document.getElementById("scanResultModal"));
  modal.show();
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
