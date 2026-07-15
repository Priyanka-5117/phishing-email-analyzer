# Phishing Email Analyzer

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![VirusTotal](https://img.shields.io/badge/API-VirusTotal-orange?style=for-the-badge)
![AbuseIPDB](https://img.shields.io/badge/API-AbuseIPDB-red?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE-T1566_Phishing-yellow?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

---

## Overview

A Python-based automated phishing email analysis tool built for SOC analysts. 
This tool replicates the manual phishing triage process performed by L1 SOC 
analysts daily — extracting IOCs, checking email authentication, querying 
threat intelligence APIs, and generating a structured risk report automatically.

**Problem it solves:** L1 SOC analysts spend 40% of their time manually 
triaging phishing emails. This tool automates the entire process in seconds.

---

## What It Does
```
Input:  Raw phishing email (.eml file)
           │
           ▼
    ┌──────────────────┐
    │  Parse Headers   │ → From, To, Subject, Reply-To, Return-Path
    └──────────────────┘
           │
           ▼
    ┌──────────────────┐
    │  Check Auth      │ → SPF, DKIM, DMARC validation
    └──────────────────┘
           │
           ▼
    ┌──────────────────┐
    │  Extract IOCs    │ → IPs, URLs, Domains from headers + body
    └──────────────────┘
           │
           ▼
    ┌──────────────────┐
    │  Threat Intel    │ → VirusTotal API + AbuseIPDB API lookups
    └──────────────────┘
           │
           ▼
    ┌──────────────────┐
    │  Risk Scoring    │ → 0-100 score with breakdown
    └──────────────────┘
           │
           ▼
Output: JSON Report + Terminal Summary + Verdict
```
---

## Features

| Feature | Description |
|---|---|
| Email Header Parsing | Extracts all key headers from raw .eml files |
| Authentication Check | Validates SPF, DKIM, DMARC results |
| IOC Extraction | Regex-based extraction of IPs, URLs, domains |
| VirusTotal Integration | Queries VT API for malicious indicator detection |
| AbuseIPDB Integration | Checks sender IP reputation and abuse history |
| Risk Scoring | Calculates 0-100 risk score with full breakdown |
| JSON Report | Generates structured report for SIEM ingestion |
| Colored Output | Terminal output with color-coded severity levels |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/YOURUSERNAME/phishing-analyzer.git
cd phishing-analyzer

# Install dependencies
pip install requests dnspython python-dotenv colorama
```

---

## API Keys Required

| API | Free Tier | Get Key |
|---|---|---|
| VirusTotal | 4 requests/minute | virustotal.com |
| AbuseIPDB | 1000 requests/day | abuseipdb.com |

Add your keys in `analyzer.py`:

```python
VIRUSTOTAL_API_KEY = "your_key_here"
ABUSEIPDB_API_KEY  = "your_key_here"
```

---

## Usage

```bash
# Basic usage
python analyzer.py sample_phishing.eml

# Save report to custom file
python analyzer.py sample_phishing.eml --output my_report.json
```

---


## Sample Output

```
╔═══════════════════════════════════════════════════╗
║         🛡️  PHISHING EMAIL ANALYZER               ║
║     IOC Extraction + Threat Intel + Risk Score    ║
║         MITRE ATT&CK: T1566 — Phishing           ║
╚═══════════════════════════════════════════════════╝

[*] Parsing email: sample_phishing.eml

EMAIL SUMMARY:
   From:    PayPal Security <security@paypa1-verify.com>
   To:      victim@gmail.com
   Subject: URGENT: Your account has been suspended!

[*] Extracting IOCs...
    ✅ IPs found:     0
    ✅ URLs found:    2
    ✅ Domains found: 6

[*] Analyzing email authentication...
    SPF:   FAIL ❌
    DKIM:  FAIL ❌
    DMARC: FAIL ❌

RISK ASSESSMENT:
   Score:  50/100
   Level:  🟠 HIGH
   Verdict: PHISHING DETECTED

✅ Full report saved to: phishing_report.json
```

---

## Repository Structure

```
phishing-analyzer/
├── analyzer.py              ← Main analysis tool
├── README.md                ← You are here
└── samples/
    ├── sample_phishing.eml  ← Sample phishing email
    └── phishing_report.json ← Sample JSON output report
```

---

## Risk Scoring System

| Score | Level | Meaning |
|---|---|---|
| 75-100 | 🔴 CRITICAL | Confirmed phishing — block immediately |
| 50-74 | 🟠 HIGH | Very likely phishing — escalate to L2 |
| 25-49 | 🟡 MEDIUM | Suspicious — investigate further |
| 0-24 | 🟢 LOW | Likely legitimate |

### Score Breakdown

| Factor | Points |
|---|---|
| SPF check failed | +20 |
| DKIM signature missing | +15 |
| DMARC check failed | +15 |
| VirusTotal malicious detection | +2 per detection (max 20) |
| AbuseIPDB score >50% | +15 |
| AbuseIPDB score >20% | +8 |
| High URL count (>5) | +10 |

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Initial Access |
| Technique | T1566 — Phishing |
| Sub-technique | T1566.001 — Spearphishing Attachment |
| Sub-technique | T1566.002 — Spearphishing Link |
| Platform | Windows, Linux, macOS |

---

