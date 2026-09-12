// Popup script
document.addEventListener("DOMContentLoaded", () => {
  const statusElem = document.getElementById("agent-status");
  const container = document.getElementById("events-container");

  const serverElem = document.getElementById("server-address");

  // Check agent health
  chrome.runtime.sendMessage({ type: "CHECK_AGENT_HEALTH" }, (res) => {
    if (res && res.online) {
      statusElem.textContent = "● Guarding (172.24.143.236)";
      statusElem.className = "status-badge";
      if (serverElem && res.endpoint) {
        serverElem.textContent = res.endpoint;
      }
    } else {
      statusElem.textContent = "○ Connecting...";
      statusElem.className = "status-badge offline";
    }
  });

  // Load recent events
  chrome.storage.local.get({ recentEvents: [] }, (res) => {
    const events = res.recentEvents || [];
    if (events.length > 0) {
      container.innerHTML = events.map(e => {
        let badgeCls = "badge-allow";
        if (e.action === "BLOCK") badgeCls = "badge-block";
        else if (e.action === "WARN") badgeCls = "badge-warn";

        return `
          <div class="event-item">
            <div>
              <div style="font-weight: 600; color: #f1f5f9;">${e.fileName}</div>
              <div style="font-size: 10px; color: #64748b;">${e.application}</div>
            </div>
            <span class="badge ${badgeCls}">${e.action}</span>
          </div>
        `;
      }).join("");
    }
  });
});
