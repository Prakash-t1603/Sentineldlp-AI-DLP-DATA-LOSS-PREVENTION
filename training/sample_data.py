"""
SentinelDLP - Synthetic Corpus Generator for DLP Content Classifier Training
Generates diverse enterprise documents across 5 sensitivity tiers and categories.
"""

from typing import List, Tuple, Dict

# Synthetic corpus templates across 5 sensitivity tiers
DATASET_TEMPLATES = [
    # ==================== PUBLIC ====================
    (
        "PUBLIC", "GENERAL_CORP",
        "SentinelDLP Open Source Community Edition is licensed under Apache 2.0. "
        "Feel free to contribute to our GitHub repository. Read our public documentation online at https://sentineldlp.io/docs."
    ),
    (
        "PUBLIC", "GENERAL_CORP",
        "FOR IMMEDIATE RELEASE: Acme Corporation announces record customer satisfaction scores in Q3 2026. "
        "Our innovative AI platform helps enterprises secure their workforce seamlessly across hybrid environments."
    ),
    (
        "PUBLIC", "GENERAL_CORP",
        "Welcome to the official company blog! In this post, we explain how modern web browsers handle websocket connections "
        "and best practices for front-end performance optimization."
    ),
    (
        "PUBLIC", "GENERAL_CORP",
        "Privacy Policy & Terms of Service: We respect your privacy. All public website visitors can browse our catalog "
        "without providing personally identifiable information unless they choose to sign up for our newsletter."
    ),
    (
        "PUBLIC", "INTELLECTUAL_PROPERTY",
        "MIT License: Copyright (c) 2026 SentinelDLP Contributors. Permission is hereby granted, free of charge, to any person "
        "obtaining a copy of this software and associated documentation files to deal in the Software without restriction."
    ),
    (
        "PUBLIC", "GENERAL_CORP",
        "Conference Agenda: Keynote Speech at 09:00 AM on Cyber Resilience and Cloud Security. "
        "Lunch break at 12:30 PM. Panel discussion on zero-trust architectures at 02:00 PM."
    ),

    # ==================== INTERNAL ====================
    (
        "INTERNAL", "GENERAL_CORP",
        "INTERNAL USE ONLY: Employee Handbook 2026 Revision. "
        "Please review the updated paid time off (PTO) guidelines, remote work stipend policies, and cafeteria operating hours."
    ),
    (
        "INTERNAL", "GENERAL_CORP",
        "Engineering All-Hands Meeting Notes: Sprint 42 retrospective. "
        "Jira tickets completed: 45, bugs resolved: 12. Next sprint focus is reducing frontend bundle size and optimizing database queries."
    ),
    (
        "INTERNAL", "GENERAL_CORP",
        "IT Support Notice: Scheduled maintenance on the internal corporate VPN gateways this Saturday from 02:00 UTC to 04:00 UTC. "
        "Internal wiki and Jira will be temporarily unreachable."
    ),
    (
        "INTERNAL", "GENERAL_CORP",
        "Company Holiday Calendar 2026 for all offices in North America, Europe, and APAC. "
        "Ensure all project deadlines are adjusted accordingly in your team roadmaps."
    ),
    (
        "INTERNAL", "GENERAL_CORP",
        "Standard Operating Procedure (SOP-401): Onboarding new developers. "
        "Step 1: Request corporate email account. Step 2: Join Slack channels. Step 3: Clone internal repositories."
    ),

    # ==================== CONFIDENTIAL ====================
    (
        "CONFIDENTIAL", "FINANCIAL",
        "CONFIDENTIAL & PROPRIETARY: Q4 Financial Forecast and Budget Allocation. "
        "Projected gross margin: 78.4%. Operating expenses: $14.2M. Projected net ARR: $85M. "
        "Do not distribute outside of executive leadership and finance committee."
    ),
    (
        "CONFIDENTIAL", "FINANCIAL",
        "Payroll and Executive Compensation Review 2026. "
        "Confidential salary bands: Engineering Level 5 base salary $185,000 + $40,000 equity grant. "
        "Bonus distribution metrics and performance multipliers attached."
    ),
    (
        "CONFIDENTIAL", "INTELLECTUAL_PROPERTY",
        "CONFIDENTIAL: Project Apex Architecture Specification and Trade Secrets. "
        "Proprietary deep neural network pruning algorithm and loss function formulation. "
        "Patented pipeline for sub-millisecond packet inspection."
    ),
    (
        "CONFIDENTIAL", "GENERAL_CORP",
        "NON-DISCLOSURE AGREEMENT (NDA) & Merger Evaluation Memorandum. "
        "Strictly confidential preliminary valuation of Target Company Beta. "
        "Enterprise value assessed at $120M subject to formal due diligence audit."
    ),
    (
        "CONFIDENTIAL", "FINANCIAL",
        "Customer Account Renewal Risk Assessment: High-value enterprise accounts with upcoming renewals. "
        "Discount approval matrix and contract renegotiation strategy."
    ),

    # ==================== RESTRICTED ====================
    (
        "RESTRICTED", "PII",
        "RESTRICTED - PII AUDIT EXPORT: "
        "Employee SSN List: John Doe SSN: 123-45-6789, Jane Smith SSN: 987-65-4321, DOB: 04/12/1988, "
        "Home Address: 742 Evergreen Terrace, Springfield."
    ),
    (
        "RESTRICTED", "FINANCIAL",
        "RESTRICTED - Cardholder Data Environment Export: "
        "Customer Name: Robert Vance, Card: 4532-0150-1234-5678, Expiry: 08/28, CVV: 742, "
        "Billing IBAN: GB29NWBK60161331926819. Strictly restricted under PCI-DSS Level 1."
    ),
    (
        "RESTRICTED", "HEALTHCARE",
        "RESTRICTED - HIPAA PROTECTED HEALTH INFORMATION (PHI): "
        "Patient ID: MRN-902148, Patient Name: Alice Walker, Diagnosis: ICD-10-CM E11.9 Type 2 Diabetes, "
        "Prescribed Medication: Metformin 500mg, Attending Physician: Dr. House."
    ),
    (
        "RESTRICTED", "PII",
        "Government ID Master Database Backup: "
        "Citizen Records: Aadhaar 4598 1234 5678, PAN ABCDE1234F, Passport US: 981273645. "
        "High-risk personal identification dataset."
    ),
    (
        "RESTRICTED", "FINANCIAL",
        "Corporate Wire Transfer Routing Instructions: "
        "Beneficiary: Acme Treasury Corp, SWIFT/BIC: CHASUS33, Account Number: 9847120391, Routing: 021000021."
    ),

    # ==================== HIGHLY_CONFIDENTIAL ====================
    (
        "HIGHLY_CONFIDENTIAL", "CREDENTIAL",
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y3L6+1hW/kY9N2Z8wQ...[REDACTED_RSA_KEY]...\n"
        "-----END RSA PRIVATE KEY-----\n"
        "Production SSL Root Certificate Private Key and decryption passkey."
    ),
    (
        "HIGHLY_CONFIDENTIAL", "CREDENTIAL",
        "CRITICAL INFRASTRUCTURE SECRETS - DO NOT COMMIT: "
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE "
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY "
        "S3_BUCKET=prod-customer-pii-vault"
    ),
    (
        "HIGHLY_CONFIDENTIAL", "CREDENTIAL",
        "DATABASE_URL=postgres://superadmin:Sup3rS3cr3tP@ssw0rd!@prod-db-primary.internal.aws.corp:5432/enterprise_dlp "
        "REDIS_AUTH=MasterAuthTokenSecretKey9876543210 "
        "JWT_SECRET=c2VudGluZWxkbHAtaGlnaGx5LXNlY3JldC10b2tlbi0yMDI2"
    ),
    (
        "HIGHLY_CONFIDENTIAL", "CREDENTIAL",
        "MASTER ENCRYPTION KEY RING: "
        "AES256_GCM_ROOT_KEY=9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e "
        "KMS_KEY_ARN=arn:aws:kms:us-east-1:123456789012:key/prod-dlp-master"
    ),
    (
        "HIGHLY_CONFIDENTIAL", "CREDENTIAL",
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
        "Server Bastion Host Root SSH Key."
    )
]


def get_training_dataset(augment_factor: int = 50) -> Tuple[List[str], List[str], List[str]]:
    """
    Generate an augmented dataset for training the DLP classifier.
    Returns (texts, tiers, categories).
    """
    texts = []
    tiers = []
    categories = []

    variations = [
        "",
        "Note: Created by automated backup task. ",
        "Confidentiality Notice applies. ",
        "Export timestamp: 2026-09-13. ",
        "Audit Log ID: 90214. ",
        "Sent via internal relay. ",
        "Document Status: Approved. "
    ]

    for factor in range(augment_factor):
        for tier, cat, text in DATASET_TEMPLATES:
            var = variations[factor % len(variations)]
            aug_text = f"{var}{text}" if factor > 0 else text
            texts.append(aug_text)
            tiers.append(tier)
            categories.append(cat)

    return texts, tiers, categories
