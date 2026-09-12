import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from agent.logger import get_agent_logger

logger = get_agent_logger("SentinelDLP.Agent.EventQueue")

QUEUE_DB_PATH = Path(__file__).resolve().parent / "logs" / "offline_events.db"
MAX_QUEUE_CAPACITY = 5000

class OfflineEventQueue:
    """
    Disk-backed persistent FIFO queue for buffering DLP events when the Central Server is offline.
    Ensures zero data loss during temporary network drops or workstation travel.
    """
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or QUEUE_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._lock, self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS queued_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    retry_count INTEGER DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queued_created ON queued_events(created_at)")
            conn.commit()

    def push(self, event_type: str, payload: Dict[str, Any]) -> bool:
        """Enqueue an event to local persistent storage."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    # Enforce queue limit to prevent disk saturation
                    cur = conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM queued_events")
                    current_count = cur.fetchone()[0]

                    if current_count >= MAX_QUEUE_CAPACITY:
                        # Drop oldest 100 events if maximum capacity reached
                        conn.execute("DELETE FROM queued_events WHERE id IN (SELECT id FROM queued_events ORDER BY id ASC LIMIT 100)")

                    conn.execute(
                        "INSERT INTO queued_events (event_type, payload_json, created_at, retry_count) VALUES (?, ?, ?, 0)",
                        (event_type, json.dumps(payload), time.time())
                    )
                    conn.commit()
                    logger.warning(f"Buffered {event_type} event to local offline queue (Queue size: {current_count + 1})")
                    return True
            except Exception as e:
                logger.error(f"Failed to buffer event to offline queue: {e}")
                return False

    def peek_batch(self, limit: int = 25) -> List[Tuple[int, str, Dict[str, Any]]]:
        """Retrieve the oldest batch of queued events without deleting them."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, event_type, payload_json FROM queued_events ORDER BY id ASC LIMIT ?", (limit,))
                    rows = cur.fetchall()
                    results = []
                    for row in rows:
                        try:
                            results.append((row["id"], row["event_type"], json.loads(row["payload_json"])))
                        except Exception:
                            # Drop corrupt row
                            conn.execute("DELETE FROM queued_events WHERE id = ?", (row["id"],))
                    return results
            except Exception as e:
                logger.error(f"Error reading offline queue batch: {e}")
                return []

    def delete_batch(self, item_ids: List[int]) -> int:
        """Acknowledge and remove successfully uploaded events."""
        if not item_ids:
            return 0
        with self._lock:
            try:
                with self._get_connection() as conn:
                    placeholders = ",".join("?" for _ in item_ids)
                    cur = conn.cursor()
                    cur.execute(f"DELETE FROM queued_events WHERE id IN ({placeholders})", item_ids)
                    conn.commit()
                    return cur.rowcount
            except Exception as e:
                logger.error(f"Error clearing queued events batch: {e}")
                return 0

    def size(self) -> int:
        """Return the current number of queued events."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM queued_events")
                    return cur.fetchone()[0]
            except Exception:
                return 0

    def clear(self):
        """Purge all queued events."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute("DELETE FROM queued_events")
                    conn.commit()
            except Exception:
                pass

event_queue = OfflineEventQueue()
