// SentinelDLP Browser Extension Service Worker
const AGENT_ENDPOINTS = [
  "http://127.0.0.1:8765/browser-event",
  "http://127.0.0.1:8766/browser-event",
  "http://127.0.0.1:8767/browser-event"
];
const HEALTH_ENDPOINTS = [
  "http://127.0.0.1:8765/health",
  "http://127.0.0.1:8766/health",
  "http://127.0.0.1:8767/health"
];

console.log("[SentinelDLP Background] Enterprise Browser Agent Initialized.");

async function postWithFallback(payload) {
  for (const endpoint of AGENT_ENDPOINTS) {
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Agent-Secret": "sentinel_agent_telemetry_secure_token_key_9981"
        },
        body: JSON.stringify(payload)
      });
      if (response.ok) {
        return await response.json();
      }
    } catch (err) {
      // Continue to next endpoint
    }
  }
  throw new Error("Unable to reach local SentinelDLP Agent (port 8765) or Central Server (port 8000)");
}

async function checkHealthWithFallback() {
  for (const endpoint of HEALTH_ENDPOINTS) {
    try {
      const response = await fetch(endpoint);
      if (response.ok) {
        const data = await response.json();
        return { online: true, details: data, endpoint: endpoint };
      }
    } catch (err) {
      // Continue
    }
  }
  return { online: false };
}

// Handle messages from content.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "DLP_FILE_UPLOAD_EVENT") {
    console.log("[SentinelDLP Background] Intercepted file upload event:", message.payload);

    postWithFallback(message.payload)
      .then((data) => {
        console.log("[SentinelDLP Background] DLP Scan Decision:", data);

        // Store recent activity in chrome.storage
        chrome.storage.local.get({ recentEvents: [] }, (res) => {
          const events = res.recentEvents || [];
          events.unshift({
            timestamp: new Date().toISOString(),
            fileName: message.payload.file_name,
            application: message.payload.application,
            domain: message.payload.domain,
            action: data.action,
            riskScore: data.risk_score,
            riskLevel: data.risk_level
          });
          chrome.storage.local.set({ recentEvents: events.slice(0, 20) });
        });

        sendResponse({ success: true, decision: data });
      })
      .catch((error) => {
        console.warn("[SentinelDLP Background] Could not reach SentinelDLP Agent:", error);
        sendResponse({
          success: false,
          error: error.message,
          decision: { action: "ALLOW", risk_score: 0.0, risk_level: "LOW" }
        });
      });

    return true; // Keep message channel open for async response
  }

  if (message.type === "CHECK_AGENT_HEALTH") {
    checkHealthWithFallback().then((res) => sendResponse(res));
    return true;
  }
});
