"""
SentinelDLP - Model Evaluation and Benchmarking Suite
Evaluates full AI/ML/NLP/Entity detection pipeline against standard test scenarios.
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.database import SessionLocal, Base, engine
from backend.ai.pipeline import dlp_pipeline
from backend.ai.entity_detector import entity_detector
from backend.ai.nlp_engine import nlp_engine
from backend.ai.classifier import dlp_classifier


def run_benchmark():
    print("=" * 70)
    print(" SentinelDLP - Comprehensive AI Pipeline Benchmark & Evaluation")
    print("=" * 70)

    test_cases = [
        {
            "name": "RSA Private Key Leak",
            "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y3L6+1hW/kY9N2Z8wQ...\n-----END RSA PRIVATE KEY-----",
            "expected_tier": "HIGHLY_CONFIDENTIAL",
            "expected_category": "CREDENTIAL",
            "expected_risk": "CRITICAL"
        },
        {
            "name": "AWS Root Credentials",
            "content": "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "expected_tier": "HIGHLY_CONFIDENTIAL",
            "expected_category": "CREDENTIAL",
            "expected_risk": "CRITICAL"
        },
        {
            "name": "PCI-DSS Cardholder Data",
            "content": "Customer payment record: Card 4532-0150-1234-5678, Exp 09/27, CVV 881, billing name Jane Doe",
            "expected_tier": "RESTRICTED",
            "expected_category": "FINANCIAL",
            "expected_risk": "HIGH"
        },
        {
            "name": "HIPAA Medical Records",
            "content": "Patient MRN-891234 admitted for ICD-10 acute hypertension. Medication: Lisinopril 20mg daily.",
            "expected_tier": "RESTRICTED",
            "expected_category": "HEALTHCARE",
            "expected_risk": "HIGH"
        },
        {
            "name": "Executive Salary & Budget",
            "content": "CONFIDENTIAL & PROPRIETARY: Executive payroll breakdown and Q4 budget allocation roadmap.",
            "expected_tier": "CONFIDENTIAL",
            "expected_category": "FINANCIAL",
            "expected_risk": "MEDIUM"
        },
        {
            "name": "Internal Engineering Sprint Notes",
            "content": "INTERNAL USE ONLY: Team standup notes. Sprint 14 backlog refinement and Jira sprint goals.",
            "expected_tier": "INTERNAL",
            "expected_category": "GENERAL_CORP",
            "expected_risk": "LOW"
        },
        {
            "name": "Public Open Source Documentation",
            "content": "SentinelDLP is an enterprise Data Loss Prevention engine licensed under the Apache License 2.0.",
            "expected_tier": "PUBLIC",
            "expected_category": "GENERAL_CORP",
            "expected_risk": "LOW"
        }
    ]

    db = SessionLocal()
    passed = 0
    total = len(test_cases)

    for idx, tc in enumerate(test_cases, 1):
        print(f"\n[Test {idx}/{total}] Scenario: {tc['name']}")
        res = dlp_pipeline.analyze_payload(
            db=db,
            content=tc["content"],
            filename="benchmark_sample.txt",
            persist=False
        )

        tier_match = res.classification == tc["expected_tier"]
        cat_match = res.category == tc["expected_category"]
        expected_r = tc["expected_risk"]
        if isinstance(expected_r, list):
            risk_match = res.risk_level in expected_r
        else:
            risk_match = res.risk_level == expected_r or (expected_r in ("HIGH", "CRITICAL") and res.risk_level in ("HIGH", "CRITICAL")) or (expected_r in ("LOW", "MEDIUM") and res.risk_level in ("LOW", "MEDIUM"))

        status = "PASSED" if (tier_match and risk_match) else "FAILED"
        if status == "PASSED":
            passed += 1

        print(f"  Result: [{status}]")
        print(f"  - Predicted Tier:     {res.classification} (Expected: {tc['expected_tier']})")
        print(f"  - Predicted Category: {res.category} (Expected: {tc['expected_category']})")
        print(f"  - Confidence Score:   {res.confidence * 100:.1f}%")
        print(f"  - Risk Score & Level: {res.risk_score:.1f} / 100 ({res.risk_level}) -> Policy: {res.policy_action}")
        print(f"  - Entities Detected:  {res.entity_summary}")
        print(f"  - Key Explanations:   {'; '.join(res.reasons[:2])}")

    db.close()

    print("\n" + "=" * 70)
    print(f" Benchmark Summary: {passed}/{total} Scenarios Passed ({passed/total*100:.1f}%)")
    print("=" * 70)


if __name__ == "__main__":
    run_benchmark()
