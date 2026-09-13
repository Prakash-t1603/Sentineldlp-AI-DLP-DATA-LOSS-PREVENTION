/**
 * SentinelDLP - UEBA Behavioral Analytics Frontend Logic
 */

let allProfiles = [];
let selectedEmployeeId = null;

document.addEventListener('DOMContentLoaded', () => {
  checkAuth();
  loadUEBASummary();
  loadUEBAProfiles();
  loadUEBAAnomalies();
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

async function loadUEBASummary() {
  try {
    const res = await fetch('/api/v1/ueba/summary', { headers: getAuthHeaders() });
    if (res.status === 401) {
      if (typeof API !== 'undefined' && API.clearAuth) API.clearAuth();
      window.location.href = '/login';
      return;
    }
    if (!res.ok) return;
    const data = await res.json();
    document.getElementById('kpi-total-profiled').textContent = data.total_employees_profiled || 0;
    document.getElementById('kpi-normal-users').textContent = data.normal_employees || 0;
    document.getElementById('kpi-suspicious-users').textContent = data.suspicious_employees || 0;
    document.getElementById('kpi-critical-anomalies').textContent = data.total_anomalies_flagged || 0;
  } catch (err) {
    console.error('Failed to load UEBA summary:', err);
  }
}

async function loadUEBAProfiles() {
  const select = document.getElementById('employee-profile-select');
  try {
    const res = await fetch('/api/v1/ueba/profiles', { headers: getAuthHeaders() });
    if (res.status === 401) {
      if (typeof API !== 'undefined' && API.clearAuth) API.clearAuth();
      window.location.href = '/login';
      return;
    }
    if (!res.ok) {
      select.innerHTML = '<option value="">Failed to load profiles</option>';
      return;
    }
    allProfiles = await res.json();
    if (!allProfiles || allProfiles.length === 0) {
      select.innerHTML = '<option value="">No employee profiles found</option>';
      return;
    }

    select.innerHTML = allProfiles.map(p => `
      <option value="${p.employee_id}">${p.employee_id} - Dept: ${p.department || 'General'} [Score: ${p.current_anomaly_score.toFixed(2)}]</option>
    `).join('');

    if (allProfiles.length > 0) {
      selectEmployeeProfile(allProfiles[0].employee_id);
    }
  } catch (err) {
    select.innerHTML = `<option value="">Error: ${err.message}</option>`;
  }
}

function selectEmployeeProfile(empId) {
  selectedEmployeeId = empId;
  const profile = allProfiles.find(p => p.employee_id === empId);
  if (!profile) return;

  document.getElementById('prof-dept').textContent = profile.department || 'General';
  document.getElementById('prof-events').textContent = `${profile.total_events_observed || 0} events observed`;
  
  const scoreEl = document.getElementById('prof-score');
  scoreEl.textContent = profile.current_anomaly_score.toFixed(2);

  const statusBadge = document.getElementById('prof-status-badge');
  if (profile.anomaly_status === 'CRITICAL' || profile.current_anomaly_score >= 0.70) {
    statusBadge.className = 'badge bg-danger';
    statusBadge.textContent = 'CRITICAL ANOMALY';
    scoreEl.className = 'fw-bold text-danger fs-5';
  } else if (profile.anomaly_status === 'SUSPICIOUS' || profile.current_anomaly_score >= 0.40) {
    statusBadge.className = 'badge bg-warning text-dark';
    statusBadge.textContent = 'SUSPICIOUS';
    scoreEl.className = 'fw-bold text-warning fs-5';
  } else {
    statusBadge.className = 'badge bg-success';
    statusBadge.textContent = 'NORMAL';
    scoreEl.className = 'fw-bold text-success fs-5';
  }

  // Baseline Statistics cards
  document.getElementById('stat-mean-files').textContent = `${profile.mean_daily_files.toFixed(1)} ± ${profile.std_daily_files.toFixed(1)}`;
  document.getElementById('stat-mean-usb').textContent = profile.mean_daily_usb_copies.toFixed(2);
  document.getElementById('stat-mean-uploads').textContent = profile.mean_daily_external_uploads.toFixed(2);
  document.getElementById('stat-after-hours').textContent = `${(profile.after_hours_ratio * 100).toFixed(1)}%`;

  // Peer comparison summary text
  const peerBox = document.getElementById('peer-analysis-summary');
  if (profile.total_events_observed < 5) {
    peerBox.innerHTML = `
      <div class="text-info"><i class="fas fa-info-circle me-1"></i> Baseline Initializing: Employee has ${profile.total_events_observed} historical events (minimum 5 required for statistical scoring).</div>
    `;
  } else {
    peerBox.innerHTML = `
      <div class="text-light mb-1">
        • Baseline daily file volume: <strong class="text-white">${profile.mean_daily_files.toFixed(1)} ops/day</strong> (Normal tolerance range: ${Math.max(0, profile.mean_daily_files - 2*profile.std_daily_files).toFixed(1)} - ${(profile.mean_daily_files + 2*profile.std_daily_files).toFixed(1)} ops/day).
      </div>
      <div class="text-light mb-1">
        • USB transfer tolerance: <strong class="text-warning">${profile.mean_daily_usb_copies.toFixed(2)} ops/day</strong>.
      </div>
      <div class="text-light">
        • Work Hours Adherence: <strong class="text-cyan">${(100 - profile.after_hours_ratio*100).toFixed(1)}%</strong> of activity occurs during standard business hours (08:00 - 19:00 UTC).
      </div>
    `;
  }
}

async function recalculateSelectedBaseline() {
  if (!selectedEmployeeId) {
    alert('Please select an employee profile first.');
    return;
  }

  const btn = document.getElementById('btn-recalc-baseline');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Recalculating...';

  try {
    const res = await fetch(`/api/v1/ueba/recalculate/${selectedEmployeeId}`, {
      method: 'POST',
      headers: getAuthHeaders()
    });

    if (res.status === 401) {
      if (typeof API !== 'undefined' && API.clearAuth) API.clearAuth();
      window.location.href = '/login';
      return;
    }

    if (!res.ok) {
      alert('Recalculation failed.');
      return;
    }

    const updatedProfile = await res.json();
    const idx = allProfiles.findIndex(p => p.employee_id === selectedEmployeeId);
    if (idx >= 0) allProfiles[idx] = updatedProfile;

    selectEmployeeProfile(selectedEmployeeId);
    loadUEBASummary();
    alert(`Baseline successfully recalculated for ${selectedEmployeeId} based on ${updatedProfile.total_events_observed} events.`);
  } catch (err) {
    alert('Error: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-calculator me-1"></i> Recalculate Statistical Baseline';
  }
}

async function loadUEBAAnomalies() {
  const tbody = document.getElementById('anomalies-table-body');
  const sevFilter = document.getElementById('filter-anomaly-sev').value;

  let url = '/api/v1/ueba/anomalies?limit=50';
  if (sevFilter) url += `&severity=${sevFilter}`;

  try {
    const res = await fetch(url, { headers: getAuthHeaders() });
    if (res.status === 401) {
      if (typeof API !== 'undefined' && API.clearAuth) API.clearAuth();
      window.location.href = '/login';
      return;
    }
    if (!res.ok) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-danger py-3">Failed to load anomalies.</td></tr>';
      return;
    }

    const anomalies = await res.json();
    if (!anomalies || anomalies.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">No behavioral anomalies flagged in the selected window. Fleet is conforming to statistical baselines.</td></tr>';
      return;
    }

    tbody.innerHTML = anomalies.map(a => {
      const timeStr = a.timestamp ? new Date(a.timestamp).toLocaleString() : 'Recent';
      const sevClass = a.severity === 'CRITICAL' ? 'bg-danger' : (a.severity === 'HIGH' ? 'bg-warning text-dark' : 'bg-info text-dark');
      const zScoreFormatted = a.z_score ? `Z = +${a.z_score.toFixed(2)}` : 'N/A';

      return `
        <tr>
          <td class="text-muted small">${timeStr}</td>
          <td class="fw-bold text-white"><i class="fas fa-user-tag text-cyan me-1"></i> ${a.employee_id}</td>
          <td><span class="badge bg-dark border border-secondary text-warning">${a.anomaly_type}</span></td>
          <td><span class="badge ${sevClass}">${a.severity}</span></td>
          <td>
            <span class="text-white">${a.observed_value.toFixed(1)}</span>
            <span class="text-muted small"> (baseline: ${a.expected_value.toFixed(1)})</span>
          </td>
          <td class="text-cyan font-monospace">${zScoreFormatted}</td>
          <td class="text-light small">${a.description}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-3">Error: ${err.message}</td></tr>`;
  }
}
