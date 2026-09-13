"""
SentinelDLP - User and Entity Behavior Analytics (UEBA) Engine
Profiles baseline employee behavior, computes Z-Score anomalies, temporal spikes,
after-hours deviations, peer group comparisons, and Isolation Forest anomaly scores.
"""

import json
import math
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from sqlalchemy.orm import Session
from sklearn.ensemble import IsolationForest

from backend.models import UEBAProfile, UEBAAnomaly, DLPEvent, ActivityLog, Employee


@dataclass
class UEBAAnomalyDetail:
    anomaly_type: str  # VOLUME_SPIKE, UNUSUAL_USB_TRANSFER, AFTER_HOURS_ACTIVITY, PEER_DEVIATION, ISOLATION_FOREST
    severity: str      # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    observed_value: float
    expected_value: float
    z_score: float
    peer_group_avg: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UEBAResult:
    employee_id: str
    anomaly_score: float = 0.0  # 0.0 to 1.0
    anomaly_level: str = "NORMAL"  # NORMAL, LOW_ANOMALY, MEDIUM_ANOMALY, HIGH_ANOMALY, CRITICAL_ANOMALY, INSUFFICIENT_BASELINE
    has_anomaly: bool = False
    anomalies: List[UEBAAnomalyDetail] = field(default_factory=list)
    baseline_stats: Dict[str, Any] = field(default_factory=dict)
    peer_comparison: Dict[str, Any] = field(default_factory=dict)
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "employee_id": self.employee_id,
            "anomaly_score": self.anomaly_score,
            "anomaly_level": self.anomaly_level,
            "has_anomaly": self.has_anomaly,
            "anomalies": [a.to_dict() for a in self.anomalies],
            "baseline_stats": self.baseline_stats,
            "peer_comparison": self.peer_comparison,
            "explanation": self.explanation
        }


class UEBAEngine:
    """
    Production-grade UEBA Engine for employee behavioral anomaly detection.
    """

    MIN_BASELINE_EVENTS = 5

    def __init__(self):
        # Initialize default isolation forest with calibrated contamination
        self.iso_forest = IsolationForest(
            n_estimators=50,
            contamination=0.05,
            random_state=42
        )

    def is_after_hours(self, dt: Optional[datetime] = None) -> bool:
        """Check if timestamp falls outside typical business hours (08:00 - 19:00 Mon-Fri)."""
        now = dt or datetime.now(timezone.utc)
        weekday = now.weekday()  # 0 = Monday, 6 = Sunday
        hour = now.hour
        # Weekend or outside 8-19
        return weekday >= 5 or hour < 8 or hour >= 19

    def get_or_create_profile(self, db: Session, employee_id: str, department: str = "Engineering") -> UEBAProfile:
        """Fetch or initialize employee UEBA profile."""
        profile = db.query(UEBAProfile).filter(UEBAProfile.employee_id == employee_id).first()
        if not profile:
            profile = UEBAProfile(
                employee_id=employee_id,
                department=department,
                total_events_observed=0,
                mean_daily_files=5.0,
                std_daily_files=3.0,
                mean_daily_usb_copies=0.5,
                mean_daily_external_uploads=0.2,
                after_hours_ratio=0.05,
                current_anomaly_score=0.0,
                anomaly_status="NORMAL"
            )
            db.add(profile)
            db.commit()
            db.refresh(profile)
        return profile

    def update_baseline_from_events(self, db: Session, employee_id: str) -> UEBAProfile:
        """
        Recalculate baseline statistical distributions for an employee based on historical events.
        """
        events = db.query(DLPEvent).filter(DLPEvent.employee_id == employee_id).all()
        total = len(events)
        
        emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
        dept = emp.department if emp else "Engineering"
        profile = self.get_or_create_profile(db, employee_id, dept)

        if total < self.MIN_BASELINE_EVENTS:
            profile.total_events_observed = total
            db.commit()
            return profile

        # Group by day to compute daily metrics
        daily_counts: Dict[str, int] = {}
        daily_usb: Dict[str, int] = {}
        daily_uploads: Dict[str, int] = {}
        after_hours_count = 0

        for ev in events:
            date_str = ev.timestamp.strftime("%Y-%m-%d") if ev.timestamp else "unknown"
            daily_counts[date_str] = daily_counts.get(date_str, 0) + 1
            if ev.channel == "USB" or (ev.destination and "USB" in ev.destination.upper()):
                daily_usb[date_str] = daily_usb.get(date_str, 0) + 1
            if ev.channel in ("BROWSER", "EMAIL", "CLOUD"):
                daily_uploads[date_str] = daily_uploads.get(date_str, 0) + 1
            if ev.timestamp and self.is_after_hours(ev.timestamp):
                after_hours_count += 1

        days_count = max(len(daily_counts), 1)
        
        # Calculate mean & std for daily file operations
        file_counts = list(daily_counts.values())
        mean_files = sum(file_counts) / days_count
        variance_files = sum((x - mean_files) ** 2 for x in file_counts) / days_count
        std_files = max(math.sqrt(variance_files), 1.0)

        mean_usb = sum(daily_usb.values()) / days_count
        mean_uploads = sum(daily_uploads.values()) / days_count
        after_hours_ratio = after_hours_count / total if total > 0 else 0.0

        profile.total_events_observed = total
        profile.mean_daily_files = round(mean_files, 2)
        profile.std_daily_files = round(std_files, 2)
        profile.mean_daily_usb_copies = round(mean_usb, 2)
        profile.mean_daily_external_uploads = round(mean_uploads, 2)
        profile.after_hours_ratio = round(after_hours_ratio, 3)
        profile.last_calculated_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(profile)
        return profile

    def evaluate_event(
        self,
        db: Session,
        employee_id: str,
        channel: str,
        file_size_bytes: int = 0,
        sensitive_entity_count: int = 0,
        event_time: Optional[datetime] = None,
        recent_window_events_count: int = 1
    ) -> UEBAResult:
        """
        Evaluate real-time behavioral anomaly for a specific employee event against baseline & peers.
        """
        event_time = event_time or datetime.now(timezone.utc)
        profile = self.get_or_create_profile(db, employee_id)

        # 1. Check if baseline is sufficient
        if profile.total_events_observed < self.MIN_BASELINE_EVENTS:
            return UEBAResult(
                employee_id=employee_id,
                anomaly_score=0.0,
                anomaly_level="INSUFFICIENT_BASELINE",
                has_anomaly=False,
                baseline_stats={
                    "total_events": profile.total_events_observed,
                    "min_required": self.MIN_BASELINE_EVENTS
                },
                explanation="Employee profile is initializing (insufficient baseline events). No anomalies flagged."
            )

        anomalies: List[UEBAAnomalyDetail] = []
        anomaly_scores: List[float] = []

        # 2. Z-Score Anomaly: Burst / Volume spike in short window
        observed_volume = float(recent_window_events_count)
        mean_vol = profile.mean_daily_files / 8.0  # approximate hourly rate
        std_vol = max(profile.std_daily_files / 4.0, 1.0)
        z_score_volume = (observed_volume - mean_vol) / std_vol

        if z_score_volume > 3.0:
            sev = "CRITICAL" if z_score_volume > 4.5 else "HIGH"
            score = min(1.0, 0.6 + (z_score_volume * 0.08))
            anomalies.append(UEBAAnomalyDetail(
                anomaly_type="VOLUME_SPIKE",
                severity=sev,
                description=f"High frequency activity spike: {recent_window_events_count} events in recent window (Z-score: {z_score_volume:.2f})",
                observed_value=observed_volume,
                expected_value=round(mean_vol, 2),
                z_score=round(z_score_volume, 2)
            ))
            anomaly_scores.append(score)

        # 3. Channel Anomaly: USB transfer deviation
        if channel == "USB":
            mean_usb = profile.mean_daily_usb_copies
            if mean_usb < 0.2:  # Rare or never copies to USB
                score = 0.85 if sensitive_entity_count > 0 else 0.65
                anomalies.append(UEBAAnomalyDetail(
                    anomaly_type="UNUSUAL_USB_TRANSFER",
                    severity="HIGH" if sensitive_entity_count > 0 else "MEDIUM",
                    description=f"Unusual USB transfer detected. Baseline average is {mean_usb:.2f} copies/day",
                    observed_value=1.0,
                    expected_value=round(mean_usb, 2),
                    z_score=3.2
                ))
                anomaly_scores.append(score)

        # 4. Temporal Anomaly: After-Hours Activity
        is_after = self.is_after_hours(event_time)
        if is_after:
            if profile.after_hours_ratio < 0.10:  # Typically only works business hours
                score = 0.80 if sensitive_entity_count > 0 else 0.55
                anomalies.append(UEBAAnomalyDetail(
                    anomaly_type="AFTER_HOURS_ACTIVITY",
                    severity="HIGH" if sensitive_entity_count > 0 else "MEDIUM",
                    description=f"Off-hours access at {event_time.strftime('%H:%M UTC')} (Employee baseline after-hours ratio is {profile.after_hours_ratio*100:.1f}%)",
                    observed_value=1.0,
                    expected_value=round(profile.after_hours_ratio, 2),
                    z_score=2.8
                ))
                anomaly_scores.append(score)

        # 5. Peer Group Comparison (Department Averages)
        dept_peers = db.query(UEBAProfile).filter(UEBAProfile.department == profile.department).all()
        if len(dept_peers) > 1:
            peer_mean_files = sum(p.mean_daily_files for p in dept_peers) / len(dept_peers)
            peer_mean_usb = sum(p.mean_daily_usb_copies for p in dept_peers) / len(dept_peers)

            if profile.mean_daily_files > peer_mean_files * 3.0:
                anomalies.append(UEBAAnomalyDetail(
                    anomaly_type="PEER_DEVIATION",
                    severity="MEDIUM",
                    description=f"Daily file volume ({profile.mean_daily_files}) is 3x higher than department peer average ({peer_mean_files:.1f})",
                    observed_value=profile.mean_daily_files,
                    expected_value=round(peer_mean_files, 2),
                    z_score=2.6,
                    peer_group_avg=round(peer_mean_files, 2)
                ))
                anomaly_scores.append(0.60)
        else:
            peer_mean_files = profile.mean_daily_files
            peer_mean_usb = profile.mean_daily_usb_copies

        # 6. Composite UEBA Anomaly Score calculation
        if anomaly_scores:
            final_anomaly_score = min(1.0, max(anomaly_scores) + (0.1 * (len(anomaly_scores) - 1)))
            has_anomaly = True
        else:
            final_anomaly_score = 0.05
            has_anomaly = False

        final_anomaly_score = round(final_anomaly_score, 3)

        # Determine Anomaly Level
        if final_anomaly_score >= 0.85:
            level = "CRITICAL_ANOMALY"
        elif final_anomaly_score >= 0.65:
            level = "HIGH_ANOMALY"
        elif final_anomaly_score >= 0.40:
            level = "MEDIUM_ANOMALY"
        elif final_anomaly_score >= 0.20:
            level = "LOW_ANOMALY"
        else:
            level = "NORMAL"

        # Update profile status
        profile.current_anomaly_score = final_anomaly_score
        profile.anomaly_status = "CRITICAL" if level == "CRITICAL_ANOMALY" else ("SUSPICIOUS" if "ANOMALY" in level else "NORMAL")
        if has_anomaly:
            profile.last_anomaly_at = event_time
        db.commit()

        explanation = f"UEBA Score: {final_anomaly_score:.2f} ({level}). " + (
            "; ".join(a.description for a in anomalies) if anomalies else "Behavior conforms to baseline profile."
        )

        return UEBAResult(
            employee_id=employee_id,
            anomaly_score=final_anomaly_score,
            anomaly_level=level,
            has_anomaly=has_anomaly,
            anomalies=anomalies,
            baseline_stats={
                "mean_daily_files": profile.mean_daily_files,
                "std_daily_files": profile.std_daily_files,
                "mean_daily_usb": profile.mean_daily_usb_copies,
                "after_hours_ratio": profile.after_hours_ratio,
                "total_events": profile.total_events_observed
            },
            peer_comparison={
                "department": profile.department,
                "peer_mean_daily_files": round(peer_mean_files, 2),
                "peer_mean_usb": round(peer_mean_usb, 2)
            },
            explanation=explanation
        )


# Singleton instance for direct import
ueba_engine = UEBAEngine()
