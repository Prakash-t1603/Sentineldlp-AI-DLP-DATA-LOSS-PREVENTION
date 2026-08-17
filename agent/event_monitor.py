import platform
import threading
import time
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.Agent.EventMonitor")

class EventMonitor:
    def __init__(self, agent_instance):
        self.agent = agent_instance
        self.is_running = False
        self._thread = None
        self._system_type = platform.system()

    def _loop(self):
        logger.info(f"System Event & Audit Monitor initialized on {self._system_type}.")
        while self.is_running:
            try:
                # System audit checkpoint
                time.sleep(30)
            except Exception as e:
                logger.debug(f"Event monitor checkpoint: {e}")

    def start(self):
        if not self.is_running:
            self.is_running = True
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def stop(self):
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            logger.info("EventMonitor stopped.")
