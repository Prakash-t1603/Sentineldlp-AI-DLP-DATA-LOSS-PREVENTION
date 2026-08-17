// Dedicated Employee Workstation Portal Controller
document.addEventListener("DOMContentLoaded", () => {
  initEmployeePortal();

  document.getElementById("form-preflight-check")?.addEventListener("submit", handlePreflightCheck);
});

async function initEmployeePortal() {
  try {
    // Check if employee ID is known or fetch first available
    const emps = await API.get("/employees");
    if (emps && emps.length > 0) {
      const currentEmp = emps[0];
      document.getElementById("emp-portal-id").textContent = currentEmp.employee_id;
      document.getElementById("emp-portal-user").textContent = currentEmp.username;
      document.getElementById("emp-portal-host").textContent = currentEmp.hostname;
      document.getElementById("emp-portal-ip").textContent = currentEmp.ip_address;
      document.getElementById("emp-portal-os").textContent = currentEmp.operating_system;
      document.getElementById("emp-portal-status").innerHTML = formatStatusDot(currentEmp.status);
      document.getElementById("emp-portal-risk").innerHTML = formatRiskBadge(currentEmp.risk_score);
    }
  } catch (err) {
    console.warn("Could not load employee details automatically:", err);
  }
}

async function handlePreflightCheck(e) {
  e.preventDefault();
  const fileInput = document.getElementById("preflight-file-input");
  const checkBtn = document.getElementById("btn-run-preflight");
  const resultDiv = document.getElementById("preflight-result");

  if (!fileInput.files || fileInput.files.length === 0) {
    showToast("Please choose a file to test", "warning");
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);
  formData.append("employee_id", "EMP-PREFLIGHT-USER");

  checkBtn.disabled = true;
  checkBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i> Inspecting File Compliance...';
  resultDiv.classList.add("d-none");

  try {
    const res = await API.post("/files/upload-scan", formData);
    resultDiv.classList.remove("d-none");

    const badgeClass = res.classification === "PUBLIC" ? "alert-success" : res.classification === "INTERNAL" ? "alert-info" : "alert-danger";
    const statusIcon = res.classification === "PUBLIC" ? "fa-shield-check" : "fa-shield-exclamation";

    resultDiv.className = `alert ${badgeClass} border mt-3`;
    resultDiv.innerHTML = `
      <div class="d-flex align-items-center gap-3">
        <i class="fas ${statusIcon} fa-2x"></i>
        <div>
          <h5 class="alert-heading mb-1">Pre-flight Assessment: ${res.classification}</h5>
          <p class="mb-1 small">Sensitivity Score: <strong>${res.sensitivity_score}/100</strong> | Confidence: <strong>${Math.round(res.confidence * 100)}%</strong></p>
          <div class="small">
            ${res.classification === 'PUBLIC' 
              ? '✅ Safe to share externally per corporate Data Loss Prevention policy.' 
              : '⚠️ Contains sensitive enterprise patterns (secrets, credentials, or confidential headers). Do NOT copy to unencrypted USB or upload to personal cloud.'}
          </div>
        </div>
      </div>
    `;
  } catch (err) {
    showToast("Pre-flight check error: " + err.message, "error");
  } finally {
    checkBtn.disabled = false;
    checkBtn.innerHTML = '<i class="fas fa-shield-alt me-2"></i> Run DLP Pre-Flight Check';
  }
}
