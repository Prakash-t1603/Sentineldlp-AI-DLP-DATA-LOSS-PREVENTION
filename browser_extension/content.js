// SentinelDLP Content Script - DOM File Upload Interceptor
(function () {
  console.log("[SentinelDLP Content] Monitoring active web page for file upload operations.");

  const currentHost = window.location.hostname.toLowerCase();

  function detectApplication(host) {
    if (host.includes("drive.google.com")) return "Google Drive";
    if (host.includes("onedrive") || host.includes("sharepoint.com")) return "OneDrive / SharePoint";
    if (host.includes("dropbox.com")) return "Dropbox";
    if (host.includes("web.whatsapp.com")) return "WhatsApp Web";
    if (host.includes("mail.google.com")) return "Gmail Webmail";
    if (host.includes("outlook.office.com") || host.includes("outlook.live.com")) return "Outlook Web";
    if (host.includes("wetransfer.com")) return "WeTransfer";
    if (host.includes("box.com")) return "Box Cloud Storage";
    if (host.includes("mega.nz")) return "Mega Cloud";
    return `Web Application (${host})`;
  }

  const appName = detectApplication(currentHost);

  function showDLPNotification(fileName, decision) {
    let box = document.getElementById("sentinel-dlp-toast");
    if (!box) {
      box = document.createElement("div");
      box.id = "sentinel-dlp-toast";
      box.style.position = "fixed";
      box.style.bottom = "24px";
      box.style.right = "24px";
      box.style.zIndex = "9999999";
      box.style.padding = "14px 18px";
      box.style.borderRadius = "8px";
      box.style.fontFamily = "system-ui, -apple-system, sans-serif";
      box.style.fontSize = "13px";
      box.style.fontWeight = "500";
      box.style.boxShadow = "0 8px 24px rgba(0,0,0,0.3)";
      box.style.transition = "all 0.3s ease";
      document.body.appendChild(box);
    }

    const action = (decision.action || "ALLOW").toUpperCase();
    if (action === "BLOCK") {
      box.style.background = "#1e1b1b";
      box.style.color = "#ff4d4f";
      box.style.border = "1px solid #ff4d4f";
      box.innerHTML = `🛡️ <strong>SentinelDLP BLOCKED:</strong> '${fileName}' transfer prohibited by policy (Risk: ${decision.risk_score || 85}/100 - ${decision.risk_level || 'CRITICAL'}).`;
    } else if (action === "WARN") {
      box.style.background = "#1f1d16";
      box.style.color = "#faad14";
      box.style.border = "1px solid #faad14";
      box.innerHTML = `⚠️ <strong>SentinelDLP WARNING:</strong> Potential sensitive data in '${fileName}' transferred to ${appName}.`;
    } else {
      box.style.background = "#141c18";
      box.style.color = "#52c41a";
      box.style.border = "1px solid #52c41a";
      box.innerHTML = `✅ <strong>SentinelDLP:</strong> '${fileName}' scanned & verified clean.`;
    }

    setTimeout(() => {
      if (box) box.style.opacity = "0";
      setTimeout(() => {
        if (box && box.parentNode) box.parentNode.removeChild(box);
      }, 500);
    }, 5000);
  }

  function handleFileSelected(file, inputElement) {
    if (!file) return;

    const fileName = file.name || "pasted_file.dat";
    const fileSize = file.size || 0;
    const ext = fileName.includes(".") ? `.${fileName.split(".").pop().toLowerCase()}` : "";

    console.log(`[SentinelDLP Content] File interception initiated: '${fileName}' (${fileSize} bytes) on ${appName}`);

    // Read full file as DataURL to cleanly obtain base64 bytes for both text and binary (images, pdfs, docs)
    const reader = new FileReader();
    reader.onload = function (e) {
      let b64 = "";
      let textSnippet = "";
      try {
        const result = e.target.result;
        if (typeof result === "string" && result.includes(",")) {
          b64 = result.split(",")[1]; // Clean base64 payload
        }
      } catch (err) {
        console.warn("[SentinelDLP Content] Base64 encoding error:", err);
      }

      const payload = {
        channel: "BROWSER",
        application: appName,
        destination: currentHost,
        domain: currentHost,
        file_name: fileName,
        file_size: fileSize,
        file_extension: ext,
        browser: navigator.userAgent.includes("Edg") ? "Microsoft Edge" : (navigator.userAgent.includes("Chrome") ? "Google Chrome" : "Browser"),
        extracted_text: textSnippet,
        file_content_base64: b64,
        timestamp: new Date().toISOString(),
        status: "PENDING_SCAN"
      };

      chrome.runtime.sendMessage(
        { type: "DLP_FILE_UPLOAD_EVENT", payload: payload },
        function (response) {
          if (response && response.decision) {
            showDLPNotification(fileName, response.decision);

            if (response.decision.action === "BLOCK") {
              if (inputElement) {
                try {
                  inputElement.value = ""; // Clear file input element
                } catch (e) {}
              }
            }
          }
        }
      );
    };

    reader.onerror = function (err) {
      console.warn("[SentinelDLP Content] FileReader error:", err);
    };

    // Always read as DataURL so binary files (images, PDFs, DOCX, XLSX) retain 100% integrity
    reader.readAsDataURL(file);
  }

  // Intercept file input change events
  document.addEventListener("change", function (event) {
    if (event.target && event.target.tagName === "INPUT" && event.target.type === "file") {
      const files = event.target.files;
      if (files && files.length > 0) {
        for (let i = 0; i < files.length; i++) {
          handleFileSelected(files[i], event.target);
        }
      }
    }
  }, true);

  // Intercept Drag-and-Drop file uploads
  document.addEventListener("drop", function (event) {
    if (event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files.length > 0) {
      for (let i = 0; i < event.dataTransfer.files.length; i++) {
        handleFileSelected(event.dataTransfer.files[i], null);
      }
    }
  }, true);

  // Intercept Clipboard Paste file/image uploads
  document.addEventListener("paste", function (event) {
    if (event.clipboardData && event.clipboardData.files && event.clipboardData.files.length > 0) {
      for (let i = 0; i < event.clipboardData.files.length; i++) {
        handleFileSelected(event.clipboardData.files[i], null);
      }
    }
  }, true);
})();
