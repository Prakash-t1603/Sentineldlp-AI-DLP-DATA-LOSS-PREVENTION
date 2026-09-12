from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.models import DLPPolicy, DLPEvent
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.PolicyService")

DEFAULT_POLICIES = [
    {
        "name": "Critical Threat Strict Prevention",
        "channel": "ALL",
        "min_risk_score": 80.0,
        "destination_type": "ALL",
        "require_sensitive_data": False,
        "action": "BLOCK",
        "create_alert": True,
        "is_active": True
    },
    {
        "name": "External Email Attachment Exfiltration Guard",
        "channel": "EMAIL",
        "min_risk_score": 60.0,
        "destination_type": "EXTERNAL",
        "require_sensitive_data": True,
        "action": "BLOCK",
        "create_alert": True,
        "is_active": True
    },
    {
        "name": "Cloud Storage & Web Upload Leak Policy",
        "channel": "BROWSER",
        "min_risk_score": 60.0,
        "destination_type": "EXTERNAL",
        "require_sensitive_data": True,
        "action": "BLOCK",
        "create_alert": True,
        "is_active": True
    },
    {
        "name": "Removable USB Sensitive Copy Policy",
        "channel": "USB",
        "min_risk_score": 60.0,
        "destination_type": "REMOVABLE",
        "require_sensitive_data": True,
        "action": "BLOCK",
        "create_alert": True,
        "is_active": True
    },
    {
        "name": "Medium Risk User Warning Policy",
        "channel": "ALL",
        "min_risk_score": 30.0,
        "destination_type": "ALL",
        "require_sensitive_data": False,
        "action": "WARN",
        "create_alert": True,
        "is_active": True
    },
    {
        "name": "Low Risk Benign Traffic Allow Policy",
        "channel": "ALL",
        "min_risk_score": 0.0,
        "destination_type": "ALL",
        "require_sensitive_data": False,
        "action": "ALLOW",
        "create_alert": False,
        "is_active": True
    }
]

class PolicyService:
    def seed_default_policies(self, db: Session) -> int:
        """Seed default enterprise DLP policies if none exist."""
        try:
            count = db.query(DLPPolicy).count()
            if count == 0:
                for pol_data in DEFAULT_POLICIES:
                    p = DLPPolicy(**pol_data)
                    db.add(p)
                db.commit()
                logger.info(f"Seeded {len(DEFAULT_POLICIES)} default DLP policies.")
                return len(DEFAULT_POLICIES)
            return 0
        except Exception as e:
            db.rollback()
            logger.error(f"Error seeding default policies: {e}")
            return 0

    def evaluate_policy(
        self,
        db: Optional[Session],
        channel: str,
        risk_score: float,
        sensitive_data_detected: bool,
        destination: Optional[str] = None,
        destination_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Evaluate DLP policy rules to determine the action: ALLOW, WARN, or BLOCK.
        """
        channel_upper = (channel or "ALL").upper()
        dest_upper = (destination_type or "ALL").upper()

        # Deduce destination type if not provided
        if not destination_type and destination:
            d_lower = destination.lower()
            if any(ext in d_lower for ext in ["drive.google", "dropbox", "onedrive", "box.com", "wetransfer", "web.whatsapp", "@"]):
                dest_upper = "EXTERNAL"
            elif any(d_lower.startswith(prefix) for prefix in ["e:", "f:", "g:", "d:", "/media", "/mnt", "/run/media"]):
                dest_upper = "REMOVABLE"
            elif any(internal in d_lower for internal in ["corp.local", "company.internal", "localhost", "127.0.0.1"]):
                dest_upper = "INTERNAL"
            else:
                dest_upper = "EXTERNAL"

        # 1. Fetch active policies ordered by min_risk_score DESC (strictest first)
        policies: List[DLPPolicy] = []
        if db:
            try:
                policies = (
                    db.query(DLPPolicy)
                    .filter(DLPPolicy.is_active == True)
                    .order_by(DLPPolicy.min_risk_score.desc())
                    .all()
                )
            except Exception as e:
                logger.warning(f"Could not load database policies: {e}")

        # If no DB policies found, use in-memory defaults
        if not policies:
            # Evaluate using default rules
            if risk_score >= 80.0:
                return {
                    "action": "BLOCK",
                    "policy_name": "Default Critical Threat Strict Prevention",
                    "create_alert": True,
                    "reason": f"Risk score ({risk_score}/100) exceeds Critical threshold."
                }
            elif risk_score >= 60.0:
                if sensitive_data_detected or dest_upper in ["EXTERNAL", "REMOVABLE"]:
                    return {
                        "action": "BLOCK",
                        "policy_name": "Default High Risk Exfiltration Prevention",
                        "create_alert": True,
                        "reason": f"High risk transfer ({risk_score}/100) targeting {dest_upper} destination with sensitive data."
                    }
                return {
                    "action": "WARN",
                    "policy_name": "Default High Risk Warning",
                    "create_alert": True,
                    "reason": f"High risk activity detected ({risk_score}/100)."
                }
            elif risk_score >= 30.0:
                return {
                    "action": "WARN",
                    "policy_name": "Default Medium Risk Warning",
                    "create_alert": True,
                    "reason": f"Medium risk activity detected ({risk_score}/100)."
                }
            else:
                return {
                    "action": "ALLOW",
                    "policy_name": "Default Low Risk Allow",
                    "create_alert": False,
                    "reason": "Normal / benign traffic."
                }

        # 2. Match against active DB policies
        for pol in policies:
            # Check channel match
            if pol.channel != "ALL" and pol.channel.upper() != channel_upper:
                continue

            # Check destination type match
            if pol.destination_type != "ALL" and pol.destination_type.upper() != dest_upper:
                continue

            # Check sensitive data requirement
            if pol.require_sensitive_data and not sensitive_data_detected:
                continue

            # Check risk threshold
            if risk_score >= pol.min_risk_score:
                return {
                    "action": pol.action.upper(),
                    "policy_name": pol.name,
                    "create_alert": pol.create_alert,
                    "reason": f"Matched policy '{pol.name}' (Min Risk: {pol.min_risk_score}, Action: {pol.action})."
                }

        # Fallback if no specific policy matched
        return {
            "action": "ALLOW",
            "policy_name": "Default Fallback Allow",
            "create_alert": False,
            "reason": "No restrictive policy matched."
        }

policy_service = PolicyService()
