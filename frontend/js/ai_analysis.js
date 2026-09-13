/**
 * SentinelDLP - AI Analysis & ML Engine Frontend Logic
 */

let currentAnalysisResult = null;

const PRESETS = {
  rsa_key: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3L6+1hW/kY9N2Z8wQ9a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
q7r8s9t0u1v2w3x4y5z6A7B8C9D0E1F2G3H4I5J6K7L8M9N0O1P2Q3R4S5T6U7V8W9X
-----END RSA PRIVATE KEY-----
export DATABASE_URL="postgres://superadmin:MasterProdPass123!@db-prod.internal.corp:5432/main"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,

  aws_keys: `[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
s3_bucket = production-customer-pii-backup-2026`,

  pci_card: `CUSTOMER PAYMENT DISPUTE AUDIT:
Customer Name: Robert Vance
Cardholder Number: 4532-0150-1234-5671
Card Brand: Visa Corporate Gold
Expiry Date: 08/28
CVV/CVC: 742
Billing Address: 124 Conch Street, Bikini Bottom
IBAN: GB29NWBK60161331926819`,

  hipaa_phi: `CONFIDENTIAL MEDICAL RECORD EXPORT (HIPAA PHI):
Patient ID: MRN-902148
Patient Full Name: Alice Walker
Date of Birth: 04/12/1988
Diagnosis: ICD-10-CM E11.9 Type 2 Diabetes Mellitus with Acute Neuropathy
Prescribed Medications: Metformin 500mg, Lisinopril 20mg Daily
Attending Physician: Dr. House, MD`,

  mna_leak: `STRICTLY CONFIDENTIAL & PROPRIETARY - NON-DISCLOSURE AGREEMENT (NDA):
Merger & Acquisition Evaluation Memorandum for Target Company Beta.
Preliminary Enterprise Valuation: $120,000,000.
Do not distribute outside of executive leadership and M&A legal advisory committee.
Bypass internal communication restrictions.`,

  safe_doc: `SentinelDLP is an enterprise Data Loss Prevention platform.
Licensed under the Apache License, Version 2.0 (the "License").
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Public developer documentation and installation guide.`
};

document.addEventListener('DOMContentLoaded', () => {
  checkAuth();
  loadAIStats();
  loadModelRegistry();
  loadAnalysisHistory();
});

function getAuthHeaders(isJson = true) {
  const token = (typeof API !== 'undefined' && API.getToken) ? API.getToken() : (localStorage.getItem('sentinel_token') || localStorage.getItem('access_token') || '');
  const headers = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (isJson) {
    headers['Content-Type'] = 'application/json';
  }
  return headers;
}

function checkAuth() {
  const token = (typeof API !== 'undefined' && API.getToken) ? API.getToken() : (localStorage.getItem('sentinel_token') || localStorage.getItem('access_token'));
  const user = (typeof API !== 'undefined' && API.getUser) ? API.getUser() : JSON.parse(localStorage.getItem('sentinel_user') || localStorage.getItem('user') || '{}');
  if (!token && window.location.pathname !== '/login') {
    window.location.href = '/login';
    return;
  }
  if (user && (user.username || user.email)) {
    document.querySelectorAll('.current-user-name').forEach(el => el.textContent = user.username || user.email || 'Analyst');
    document.querySelectorAll('.current-user-role').forEach(el => el.textContent = (user.role || 'ANALYST').toUpperCase());
  }
}

function switchSandboxMode(mode) {
  if (mode === 'text') {
    document.getElementById('sandbox-text-mode').classList.remove('d-none');
    document.getElementById('sandbox-file-mode').classList.add('d-none');
    document.getElementById('tab-text-btn').classList.add('active');
    document.getElementById('tab-file-btn').classList.remove('active');
  } else {
    document.getElementById('sandbox-text-mode').classList.add('d-none');
    document.getElementById('sandbox-file-mode').classList.remove('d-none');
    document.getElementById('tab-text-btn').classList.remove('active');
    document.getElementById('tab-file-btn').classList.add('active');
  }
}

function loadPresetSample(presetKey) {
  if (presetKey && PRESETS[presetKey]) {
    document.getElementById('sandbox-text-input').value = PRESETS[presetKey];
    if (presetKey === 'rsa_key' || presetKey === 'aws_keys') {
      document.getElementById('sandbox-filename').value = '.env.production';
    } else if (presetKey === 'pci_card') {
      document.getElementById('sandbox-filename').value = 'customer_transactions.csv';
    } else if (presetKey === 'hipaa_phi') {
      document.getElementById('sandbox-filename').value = 'patient_records.json';
    } else {
      document.getElementById('sandbox-filename').value = 'document.txt';
    }
  }
}

async function loadAIStats() {
  try {
    const res = await fetch('/api/v1/ai/stats', { headers: getAuthHeaders() });
    if (res.status === 401) {
      if (typeof API !== 'undefined' && API.clearAuth) API.clearAuth();
      window.location.href = '/login';
      return;
    }
    if (!res.ok) return;
    const data = await res.json();
    document.getElementById('kpi-total-inspected').textContent = data.total_analyses || 0;
    document.getElementById('kpi-ai-blocked').textContent = data.blocked_transfers || 0;
    document.getElementById('kpi-ai-warned').textContent = data.warned_transfers || 0;
    document.getElementById('kpi-ocr-files').textContent = data.ocr_processed_files || 0;
  } catch (err) {
    console.error('Failed to load AI stats:', err);
  }
}

async function loadModelRegistry() {
  const tbody = document.getElementById('models-table-body');
  try {
    const res = await fetch('/api/v1/ai/models', { headers: getAuthHeaders() });
    if (res.status === 401) {
      if (typeof API !== 'undefined' && API.clearAuth) API.clearAuth();
      window.location.href = '/login';
      return;
    }
    if (!res.ok) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-danger py-3">Failed to load model registry.</td></tr>';
      return;
    }
    const models = await res.json();
    if (!models || models.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">No AI models registered.</td></tr>';
      return;
    }

    tbody.innerHTML = models.map(m => `
      <tr>
        <td class="fw-bold text-white"><i class="fas fa-cube text-cyan me-1"></i> ${m.model_name}</td>
        <td><span class="badge bg-dark border border-secondary text-info">${m.model_version}</span></td>
        <td><span class="badge bg-secondary bg-opacity-25 text-white">${m.model_type}</span></td>
        <td class="text-success fw-bold">${(m.precision_score * 100).toFixed(1)}%</td>
        <td class="text-info fw-bold">${(m.recall_score * 100).toFixed(1)}%</td>
        <td class="text-cyan fw-bold">${(m.f1_score * 100).toFixed(1)}%</td>
        <td class="text-muted">${m.feature_count.toLocaleString()} features</td>
        <td>
          <span class="badge bg-success bg-opacity-25 text-success border border-success">
            <i class="fas fa-circle-check me-1"></i> ${m.status}
          </span>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-3">Error: ${err.message}</td></tr>`;
  }
}

async function runTextAnalysis() {
  const text = document.getElementById('sandbox-text-input').value;
  const filename = document.getElementById('sandbox-filename').value || 'payload.txt';
  const channel = document.getElementById('sandbox-channel').value || 'FILE';
  const btn = document.getElementById('btn-run-analysis');

  if (!text || !text.trim()) {
    alert('Please enter or paste content to analyze.');
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Analyzing with Neural DLP Engine...';
  const startTime = performance.now();

  try {
    const res = await fetch('/api/v1/ai/analyze/text', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ text, filename, channel, device_id: 'SOC-SANDBOX' })
    });

    const elapsed = Math.round(performance.now() - startTime);

    if (!res.ok) {
      const err = await res.json();
      alert('Analysis failed: ' + (err.detail || 'Server error'));
      return;
    }

    const data = await res.json();
    currentAnalysisResult = data;
    renderAnalysisResult(data, elapsed);
    loadAIStats();
    loadAnalysisHistory();
  } catch (err) {
    alert('Analysis error: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-bolt me-1"></i> Execute Real-Time Multi-Tier AI Analysis';
  }
}

async function runFileUploadAnalysis() {
  const fileInput = document.getElementById('sandbox-file-input');
  const btn = document.getElementById('btn-run-file-analysis');

  if (!fileInput.files || fileInput.files.length === 0) {
    alert('Please select a file to upload and inspect.');
    return;
  }

  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append('file', file);
  formData.append('channel', 'FILE');
  formData.append('device_id', 'SOC-SANDBOX');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Extracting & Running OCR / AI Pipeline...';
  const startTime = performance.now();

  try {
    const res = await fetch('/api/v1/ai/analyze/file', {
      method: 'POST',
      headers: getAuthHeaders(false),
      body: formData
    });

    const elapsed = Math.round(performance.now() - startTime);

    if (res.status === 401) {
      if (typeof API !== 'undefined' && API.clearAuth) API.clearAuth();
      window.location.href = '/login';
      return;
    }

    if (!res.ok) {
      const err = await res.json();
      alert('File analysis failed: ' + (err.detail || 'Server error'));
      return;
    }

    const data = await res.json();
    currentAnalysisResult = data;
    renderAnalysisResult(data, elapsed);
    loadAIStats();
    loadAnalysisHistory();
  } catch (err) {
    alert('File analysis error: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-file-shield me-1"></i> Upload & Run Deep Document Inspection';
  }
}

function renderAnalysisResult(data, elapsedMs) {
  document.getElementById('sandbox-empty-state').classList.add('d-none');
  document.getElementById('sandbox-result-container').classList.remove('d-none');

  // Latency badge
  const latencyBadge = document.getElementById('analysis-latency-badge');
  latencyBadge.className = data.fast_path ? 'badge bg-success' : 'badge bg-cyan text-dark';
  latencyBadge.innerHTML = data.fast_path ?
    `<i class="fas fa-bolt me-1"></i> Fast-Path Cache Hit (${elapsedMs}ms)` :
    `<i class="fas fa-microchip me-1"></i> Deep AI Pipeline (${elapsedMs}ms)`;

  // Classification & Category
  document.getElementById('res-classification').textContent = data.classification;
  document.getElementById('res-category').textContent = data.category || 'UNCLASSIFIED';

  // Action badge & colors
  const actionBadge = document.getElementById('res-action-badge');
  const verdictBanner = document.getElementById('verdict-banner');
  const riskScore = document.getElementById('res-risk-score');
  riskScore.textContent = (data.risk_score || 0).toFixed(1);

  if (data.policy_action === 'BLOCK' || data.risk_level === 'CRITICAL') {
    actionBadge.className = 'badge bg-danger fs-6 px-3 py-2';
    actionBadge.textContent = 'BLOCK';
    verdictBanner.style.borderLeftColor = 'var(--risk-critical)';
  } else if (data.policy_action === 'WARN' || data.risk_level === 'HIGH' || data.risk_level === 'MEDIUM') {
    actionBadge.className = 'badge bg-warning text-dark fs-6 px-3 py-2';
    actionBadge.textContent = 'WARN';
    verdictBanner.style.borderLeftColor = 'var(--risk-medium)';
  } else {
    actionBadge.className = 'badge bg-success fs-6 px-3 py-2';
    actionBadge.textContent = 'ALLOW';
    verdictBanner.style.borderLeftColor = 'var(--risk-low)';
  }

  // Confidence bar
  const confPct = Math.round((data.confidence || 0) * 100);
  document.getElementById('res-confidence-val').textContent = `${confPct}%`;
  document.getElementById('res-confidence-bar').style.width = `${confPct}%`;

  // Entities list
  const entitiesList = document.getElementById('res-entities-list');
  const entities = data.detected_entities || [];
  document.getElementById('res-entity-count').textContent = entities.length;

  if (entities.length === 0) {
    entitiesList.innerHTML = '<span class="text-muted small">No sensitive entities detected in payload.</span>';
  } else {
    entitiesList.innerHTML = entities.map(e => `
      <span class="badge bg-dark border border-secondary text-light p-2 d-inline-flex align-items-center gap-1">
        <span class="badge ${getEntityCategoryBadge(e.category)}">${e.category}</span>
        <strong class="text-warning">${e.entity_type}</strong>
        <span class="text-muted font-monospace">${e.masked_value || e.masked_sample || '****'}</span>
        <span class="badge bg-secondary text-info">${Math.round((e.confidence || 1) * 100)}%</span>
      </span>
    `).join('');
  }

  // Reasons list
  const reasonsList = document.getElementById('res-reasons-list');
  const reasons = data.reasons || [];
  if (reasons.length === 0) {
    reasonsList.innerHTML = '<div>• Payload processed cleanly.</div>';
  } else {
    reasonsList.innerHTML = reasons.map(r => `<div class="mb-1 text-light"><i class="fas fa-circle-chevron-right text-cyan me-1"></i> ${r}</div>`).join('');
  }
}

function getEntityCategoryBadge(category) {
  switch ((category || '').toUpperCase()) {
    case 'CREDENTIALS': return 'bg-danger text-white';
    case 'FINANCIAL': return 'bg-warning text-dark';
    case 'IDENTITY': return 'bg-primary text-white';
    case 'HEALTH': return 'bg-danger bg-opacity-75 text-white';
    case 'CORPORATE': return 'bg-purple text-white';
    default: return 'bg-info text-dark';
  }
}

async function submitFeedback(feedbackType) {
  if (!currentAnalysisResult) {
    alert('No active analysis to provide feedback for.');
    return;
  }

  try {
    const payload = {
      analysis_id: currentAnalysisResult.id,
      event_id: currentAnalysisResult.event_id,
      feedback_type: feedbackType,
      original_classification: currentAnalysisResult.classification,
      notes: `Analyst marked as ${feedbackType}`
    };

    const res = await fetch('/api/v1/ai/feedback', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload)
    });

    if (res.ok) {
      alert(`Feedback recorded: ${feedbackType}. This will feed the model fine-tuning loop.`);
    } else {
      alert('Feedback submission failed.');
    }
  } catch (err) {
    alert('Error submitting feedback: ' + err.message);
  }
}

async function loadAnalysisHistory() {
  const tbody = document.getElementById('analyses-table-body');
  const classFilter = document.getElementById('filter-classification').value;
  const actionFilter = document.getElementById('filter-action').value;

  let url = '/api/v1/ai/analyses?limit=30';
  if (classFilter) url += `&classification=${classFilter}`;

  try {
    const res = await fetch(url, { headers: getAuthHeaders() });
    if (res.status === 401) {
      if (typeof API !== 'undefined' && API.clearAuth) API.clearAuth();
      window.location.href = '/login';
      return;
    }
    if (!res.ok) {
      tbody.innerHTML = '<tr><td colspan="9" class="text-center text-danger py-3">Failed to load analyses history.</td></tr>';
      return;
    }

    const data = await res.json();
    let items = data.items || [];
    if (actionFilter) {
      items = items.filter(i => i.policy_action === actionFilter);
    }

    if (items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted py-3">No matching AI analyses found.</td></tr>';
      return;
    }

    tbody.innerHTML = items.map(a => {
      const timeStr = a.timestamp ? new Date(a.timestamp).toLocaleString() : 'Just now';
      const actionClass = a.policy_action === 'BLOCK' ? 'bg-danger' : (a.policy_action === 'WARN' ? 'bg-warning text-dark' : 'bg-success');
      const classColor = a.classification === 'HIGHLY_CONFIDENTIAL' ? 'text-danger' : (a.classification === 'RESTRICTED' ? 'text-warning' : (a.classification === 'CONFIDENTIAL' ? 'text-info' : 'text-muted'));

      return `
        <tr>
          <td class="text-muted small">${timeStr}</td>
          <td class="fw-bold text-white"><i class="fas fa-file text-secondary me-1"></i> ${a.filename}</td>
          <td><span class="badge bg-dark border border-secondary text-info">${a.channel}</span></td>
          <td class="fw-bold ${classColor}">${a.classification}</td>
          <td class="text-cyan">${Math.round(a.confidence * 100)}%</td>
          <td><span class="badge bg-secondary">${a.detected_entities ? a.detected_entities.length : 0} entities</span></td>
          <td><span class="badge ${actionClass}">${a.policy_action}</span></td>
          <td>
            ${a.fast_path ? '<span class="badge bg-success bg-opacity-25 text-success"><i class="fas fa-bolt"></i> FAST</span>' : '<span class="badge bg-secondary text-muted">DEEP</span>'}
          </td>
          <td>
            <button class="btn btn-sm btn-outline-info" onclick='openAnalysisDetail(${JSON.stringify(a).replace(/'/g, "&#39;")})'>
              <i class="fas fa-eye"></i> View
            </button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-center text-danger py-3">Error: ${err.message}</td></tr>`;
  }
}

function openAnalysisDetail(analysis) {
  const modalContent = document.getElementById('modal-analysis-content');
  const entities = analysis.detected_entities || [];
  const reasons = analysis.reasons || [];

  modalContent.innerHTML = `
    <div class="mb-3 p-3 rounded bg-dark border border-secondary">
      <div class="row g-2">
        <div class="col-6"><strong>Filename:</strong> <span class="text-white">${analysis.filename}</span></div>
        <div class="col-6"><strong>Channel:</strong> <span class="badge bg-info text-dark">${analysis.channel}</span></div>
        <div class="col-6"><strong>Classification:</strong> <span class="fw-bold text-warning">${analysis.classification}</span></div>
        <div class="col-6"><strong>Verdict:</strong> <span class="badge bg-danger">${analysis.policy_action}</span></div>
        <div class="col-6"><strong>Confidence:</strong> <span class="text-cyan">${Math.round(analysis.confidence * 100)}%</span></div>
        <div class="col-6"><strong>Risk Score:</strong> <span class="text-white">${analysis.risk_score} / 100 (${analysis.risk_level})</span></div>
        <div class="col-12"><strong>File SHA-256:</strong> <span class="font-monospace text-muted small">${analysis.file_hash || 'N/A'}</span></div>
      </div>
    </div>

    <h6 class="text-white fw-bold"><i class="fas fa-fingerprint text-warning me-2"></i>Sensitive Entities Discovered (${entities.length})</h6>
    <div class="mb-3 p-2 rounded bg-dark" style="max-height: 150px; overflow-y: auto;">
      ${entities.length === 0 ? '<div class="text-muted small">No entities detected.</div>' : entities.map(e => `
        <div class="p-1 mb-1 border-bottom border-secondary small d-flex justify-content-between">
          <span><strong class="text-warning">[${e.category}] ${e.entity_type}:</strong> ${e.masked_value || e.masked_sample || '****'}</span>
          <span class="text-cyan">${Math.round((e.confidence || 1) * 100)}%</span>
        </div>
      `).join('')}
    </div>

    <h6 class="text-white fw-bold"><i class="fas fa-list-check text-info me-2"></i>Explainability Breakdown</h6>
    <div class="p-2 rounded bg-dark small text-white-50" style="max-height: 150px; overflow-y: auto;">
      ${reasons.map(r => `<div class="mb-1">• ${r}</div>`).join('')}
    </div>
  `;

  const modal = new bootstrap.Modal(document.getElementById('analysisDetailModal'));
  modal.show();
}
