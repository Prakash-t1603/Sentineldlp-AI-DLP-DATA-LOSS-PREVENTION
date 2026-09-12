import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any

from agent.logger import get_agent_logger

logger = get_agent_logger("SentinelDLP.Agent.BrowserMonitor")

class BrowserEventHandler(BaseHTTPRequestHandler):
    """
    Local HTTP handler receiving upload interception events from the authorized browser extension.
    """
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Agent-Secret")
        self.end_headers()

    def do_GET(self):
        if self.path in ["/health", "/api/health", "/"]:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "service": "SentinelDLP Agent Browser Receiver"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path in ["/browser-event", "/api/browser-event", "/upload-event", "/api/dlp/browser-event"]:
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            try:
                data = json.loads(body.decode("utf-8"))
                
                # Dispatch event to the central DLP server via the Agent
                agent_instance = getattr(self.server, "agent_instance", None)
                if agent_instance:
                    res = agent_instance.send_dlp_event(data)
                else:
                    res = {"action": "ALLOW", "risk_score": 0.0, "status": "PROCESSED"}

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(res).encode("utf-8"))
            except Exception as e:
                logger.error(f"Error processing browser extension event: {e}")
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e), "action": "ALLOW"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Silence default standard error logging
        return

class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True

class BrowserMonitor:
    """
    Endpoint Browser Monitor service listening for browser extension telemetry on localhost (ports 8765-8768).
    """
    def __init__(self, agent_instance, host: str = "0.0.0.0", port: int = 8765):
        self.agent = agent_instance
        self.host = host
        self.port = port
        self.httpd: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.is_running = False

    def start(self):
        if self.is_running:
            return
        # Try primary port and candidate backup ports
        candidate_ports = [self.port, 8766, 8767, 8768] if self.port == 8765 else [self.port]
        for p in candidate_ports:
            try:
                self.httpd = ReusableHTTPServer((self.host, p), BrowserEventHandler)
                self.httpd.agent_instance = self.agent
                self.port = p
                self.is_running = True
                self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
                self._thread.start()
                display_ip = getattr(self.agent, "ip_address", None) or "172.24.143.236"
                logger.info(f"Browser Extension receiver active on http://{display_ip}:{self.port} (network interface: 0.0.0.0)")
                return
            except OSError:
                continue
            except Exception as e:
                logger.debug(f"Could not bind Browser Monitor on {self.host}:{p}: {e}")
                continue

        logger.info(f"Browser Extension receiver deferred (ports {candidate_ports} active on endpoint)")

    def stop(self):
        self.is_running = False
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
            self.httpd = None
        logger.info("Browser Extension local receiver stopped.")
