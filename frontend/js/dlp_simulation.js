// SentinelDLP Interactive Simulation Studio Controller

const PRESETS = {
  USB_BENIGN: {
    channel: "USB",
    application: "USB Storage",
    destination: "E:\\Removable_Drive",
    employee_id: "EMP-DEV-01",
    file_name: "weekly_meeting_agenda.txt",
    file_size: 4096,
    content: "Team sync agenda for sprint 42:\n1. Backend API migration\n2. Documentation review\n3. UI performance benchmarks\nNo sensitive keys or credentials."
  },
  USB_SENSITIVE: {
    channel: "USB",
    application: "USB Storage",
    destination: "E:\\SanDisk_Flash",
    employee_id: "EMP-FIN-02",
    file_name: "employee_q3_salary_and_aadhaar.csv",
    file_size: 84000,
    content: "EmpID,Name,National_ID,Monthly_Salary\nEMP-101,Rahul Sharma,5489 1234 8901,₹185,000\nEMP-102,Priya Singh,7788 9900 1122,₹210,000\nEMP-103,Amit Verma,9922 3344 5566,₹145,000\nCONFIDENTIAL CORPORATE PAYROLL RECORD DO NOT DISTRIBUTE."
  },
  GDRIVE_SENSITIVE: {
    channel: "BROWSER",
    application: "Google Drive",
    destination: "drive.google.com",
    employee_id: "EMP-OPS-04",
    file_name: "production_master_credentials.env",
    file_size: 2048,
    content: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nDATABASE_URL=postgres://admin_root:SuperMasterSecret9981!@db.prod.internal:5432/main_db\nOPENAI_API_KEY=sk-proj-9999888877776666555544443333222211110000aaaa"
  },
  BROWSER_BENIGN: {
    channel: "BROWSER",
    application: "Dropbox",
    destination: "dropbox.com",
    employee_id: "EMP-MKT-05",
    file_name: "public_press_release.md",
    file_size: 6144,
    content: "# Press Release 2026\n\nWe are proud to announce the open-source release of our new community tools. All code is licensed under Apache 2.0."
  },
  EMAIL_SENSITIVE: {
    channel: "EMAIL",
    application: "Corporate Mail (Outlook)",
    destination: "external_competitor@external.com",
    employee_id: "EMP-HR-03",
    file_name: "confidential_client_tax_pans.csv",
    file_size: 15400,
    content: "Client_Name,PAN_Number,Credit_Card,Annual_Income\nAcme Corp,ABCDE1234F,4111 1111 1111 1111,$1,200,000\nGlobal Tech,BCDEF2345G,5500 0000 0000 0004,$3,400,000\nStrictly Confidential Tax and Identity Documents."
  },
  WHATSAPP_SENSITIVE: {
    channel: "BROWSER",
    application: "WhatsApp Web",
    destination: "web.whatsapp.com",
    employee_id: "EMP-DEV-01",
    file_name: "database_dump_users.sql",
    file_size: 64000,
    content: "INSERT INTO users (username, password_hash, email) VALUES ('admin', 'super_secret_hash_pwd_9981', 'admin@sentineldlp.io');\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y31gZ5z...PRIVATE KEY DUMP\n-----END RSA PRIVATE KEY-----"
  }
};

function loadPreset(presetKey) {
  const p = PRESETS[presetKey];
  if (!p) return;

  document.getElementById("sim-channel").value = p.channel;
  document.getElementById("sim-application").value = p.application;
  document.getElementById("sim-destination").value = p.destination;
  document.getElementById("sim-employee").value = p.employee_id;
  document.getElementById("sim-filename").value = p.file_name;
  document.getElementById("sim-filesize").value = p.file_size;
  document.getElementById("sim-content").value = p.content;

  if (typeof showToast === "function") {
    showToast(`Loaded scenario: ${presetKey.replace("_", " ")}`, "info");
  }

  // Auto execute for instant feedback
  executeSimulation();
}

function onChannelChange() {
  const ch = document.getElementById("sim-channel").value;
  const appInput = document.getElementById("sim-application");
  const destInput = document.getElementById("sim-destination");

  if (ch === "USB") {
    appInput.value = "USB Storage";
    destInput.value = "E:\\External_Device";
  } else if (ch === "BROWSER") {
    appInput.value = "Google Drive";
    destInput.value = "drive.google.com";
  } else if (ch === "EMAIL") {
    appInput.value = "Corporate Mail (Outlook)";
    destInput.value = "external_recipient@outside.com";
  } else if (ch === "CLOUD") {
    appInput.value = "OneDrive Sync";
    destInput.value = "C:\\Users\\Employee\\OneDrive";
  }
}

async function executeSimulation(event) {
  if (event) event.preventDefault();

  const channel = document.getElementById("sim-channel").value;
  const application = document.getElementById("sim-application").value;
  const destination = document.getElementById("sim-destination").value;
  const employee_id = document.getElementById("sim-employee").value;
  const file_name = document.getElementById("sim-filename").value;
  const file_size = parseInt(document.getElementById("sim-filesize").value, 10) || 0;
  const extracted_text = document.getElementById("sim-content").value;

  const btn = document.getElementById("btn-run-sim");
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span> Inspecting with Centralized Scanner...`;

  const payload = {
    channel: channel,
    application: application,
    destination: destination,
    employee_id: employee_id,
    file_name: file_name,
    file_size: file_size,
    extracted_text: extracted_text
  };

  try {
    const result = await API.post("/dlp/scan", payload);
    renderSimulationResult(result);
    if (typeof showToast === "function") {
      const type = result.action === "BLOCK" ? "error" : (result.action === "WARN" ? "warning" : "success");
      showToast(`DLP Decision: ${result.action} (Risk: ${result.risk_score})`, type);
    }
  } catch (err) {
    if (typeof showToast === "function") {
      showToast("Simulation error: " + err.message, "error");
    } else {
      alert("Error: " + err.message);
    }
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i class="fas fa-play me-2"></i> Run Unified DLP Inspection Pipeline`;
  }
}

function renderSimulationResult(result) {
  document.getElementById("sim-empty-state").classList.add("d-none");
  document.getElementById("sim-results-container").classList.remove("d-none");

  const action = (result.action || "ALLOW").toUpperCase();
  const banner = document.getElementById("result-action-banner");
  const actionText = document.getElementById("result-action-text");
  const riskScore = document.getElementById("result-risk-score");

  actionText.textContent = action;
  riskScore.textContent = `${result.risk_score} / 100 (${result.risk_level})`;

  if (action === "BLOCK") {
    banner.style.background = "rgba(239, 68, 68, 0.2)";
    banner.style.border = "1px solid #ef4444";
    banner.style.color = "#ef4444";
    actionText.className = "fs-4 fw-bold text-danger";
  } else if (action === "WARN") {
    banner.style.background = "rgba(245, 158, 11, 0.2)";
    banner.style.border = "1px solid #f59e0b";
    banner.style.color = "#f59e0b";
    actionText.className = "fs-4 fw-bold text-warning";
  } else {
    banner.style.background = "rgba(16, 185, 129, 0.2)";
    banner.style.border = "1px solid #10b981";
    banner.style.color = "#10b981";
    actionText.className = "fs-4 fw-bold text-success";
  }

  document.getElementById("result-classification").textContent = result.classification;
  document.getElementById("result-sensitivity").textContent = `${result.sensitivity_score} / 100`;
  document.getElementById("result-policy-name").textContent = result.policy_name;
  document.getElementById("result-status-msg").textContent = result.message;

  // Render Detected Entities
  const entitiesList = document.getElementById("result-entities-list");
  if (result.detected_entities && result.detected_entities.length > 0) {
    entitiesList.innerHTML = result.detected_entities.map(e => `
      <span class="badge bg-danger bg-opacity-25 text-danger border border-danger p-2">
        <i class="fas fa-fingerprint me-1"></i> ${e.entity_type} (x${e.count})
      </span>
    `).join("");
  } else {
    entitiesList.innerHTML = `<span class="badge bg-success bg-opacity-25 text-success border border-success p-2"><i class="fas fa-check me-1"></i> No sensitive entities identified</span>`;
  }

  // Alert Box
  const alertBox = document.getElementById("result-alert-box");
  if (result.alert_created) {
    alertBox.classList.remove("d-none");
    alertBox.className = "p-2 rounded bg-danger bg-opacity-25 border border-danger text-white small";
    alertBox.innerHTML = `<i class="fas fa-radiation text-danger me-1"></i> <strong>Real-time Alert Created!</strong> Alert #${result.alert_id || 'NEW'} opened in SOC threat center.`;
  } else {
    alertBox.classList.remove("d-none");
    alertBox.className = "p-2 rounded bg-success bg-opacity-25 border border-success text-white small";
    alertBox.innerHTML = `<i class="fas fa-shield-check text-success me-1"></i> No security alert triggered (Policy: ${result.action}).`;
  }
}
