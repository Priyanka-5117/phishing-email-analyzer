#!/usr/bin/env python3
"""
Phishing Email Analyzer
Author: Your Name
Description: Automated phishing email analysis tool with IOC extraction,
             threat intelligence lookups, and risk scoring.
MITRE ATT&CK: T1566 - Phishing
"""

import re
import json
import email
import argparse
import requests
import datetime
from email import policy
from email.parser import BytesParser
from colorama import Fore, Style, init

init(autoreset=True)

# ── API KEYS — paste yours here ──
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY  = "YOUR_ABUSEIPDB_API_KEY"

# ── Regex patterns ──
IP_PATTERN     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_PATTERN    = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
DOMAIN_PATTERN = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}')


def print_banner():
    print(Fore.CYAN + """
╔═══════════════════════════════════════════════════╗
║         🛡️  PHISHING EMAIL ANALYZER               ║
║     IOC Extraction + Threat Intel + Risk Score    ║
║         MITRE ATT&CK: T1566 — Phishing           ║
╚═══════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)


def parse_email(file_path):
    """Parse the .eml file and extract headers and body."""
    print(Fore.YELLOW + f"\n[*] Parsing email: {file_path}")
    
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    headers = {
        'from':          msg.get('From', 'N/A'),
        'to':            msg.get('To', 'N/A'),
        'subject':       msg.get('Subject', 'N/A'),
        'date':          msg.get('Date', 'N/A'),
        'reply_to':      msg.get('Reply-To', 'N/A'),
        'return_path':   msg.get('Return-Path', 'N/A'),
        'received':      msg.get_all('Received', []),
        'x_originating': msg.get('X-Originating-IP', 'N/A'),
        'message_id':    msg.get('Message-ID', 'N/A'),
        'spf':           msg.get('Received-SPF', 'N/A'),
        'dkim':          msg.get('DKIM-Signature', 'N/A'),
        'dmarc':         msg.get('Authentication-Results', 'N/A'),
    }
    
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body += part.get_content()
            elif part.get_content_type() == 'text/html':
                body += part.get_content()
    else:
        body = msg.get_content()
    
    return headers, body


def extract_iocs(headers, body):
    """Extract all IOCs from email headers and body."""
    print(Fore.YELLOW + "\n[*] Extracting IOCs...")
    
    full_text = str(headers) + " " + body
    
    ips      = list(set(IP_PATTERN.findall(full_text)))
    urls     = list(set(URL_PATTERN.findall(full_text)))
    domains  = list(set(DOMAIN_PATTERN.findall(full_text)))
    
    # Filter out private IPs
    public_ips = [ip for ip in ips if not (
        ip.startswith('192.168.') or
        ip.startswith('10.')      or
        ip.startswith('172.')     or
        ip == '127.0.0.1'
    )]
    
    print(Fore.GREEN + f"    ✅ IPs found:     {len(public_ips)}")
    print(Fore.GREEN + f"    ✅ URLs found:    {len(urls)}")
    print(Fore.GREEN + f"    ✅ Domains found: {len(domains)}")
    
    return {
        'ips':     public_ips,
        'urls':    urls,
        'domains': domains
    }


def check_virustotal(ioc, ioc_type):
    """Query VirusTotal API for an IOC."""
    if VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return {"error": "API key not set"}
    
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    else:
        return {}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                'malicious':  stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless':   stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0)
            }
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def check_abuseipdb(ip):
    """Query AbuseIPDB for IP reputation."""
    if ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY":
        return {"error": "API key not set"}
    
    headers = {
        "Key":    ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress":    ip,
        "maxAgeInDays": 90
    }
    
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                'total_reports':          data.get('totalReports', 0),
                'country_code':           data.get('countryCode', 'N/A'),
                'isp':                    data.get('isp', 'N/A'),
                'is_tor':                 data.get('isTor', False)
            }
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def analyze_authentication(headers):
    """Analyze SPF, DKIM, DMARC results."""
    print(Fore.YELLOW + "\n[*] Analyzing email authentication...")
    
    auth_results = {
        'spf_pass':   False,
        'dkim_pass':  False,
        'dmarc_pass': False,
        'spf_raw':    headers.get('spf', 'N/A'),
        'dkim_raw':   headers.get('dkim', 'N/A'),
        'dmarc_raw':  headers.get('dmarc', 'N/A'),
    }
    
    spf = str(headers.get('spf', '')).lower()
    if 'pass' in spf:
        auth_results['spf_pass'] = True
    
    dkim = str(headers.get('dkim', '')).lower()
    if dkim and dkim != 'n/a':
        auth_results['dkim_pass'] = True
    
    dmarc = str(headers.get('dmarc', '')).lower()
    if 'dmarc=pass' in dmarc:
        auth_results['dmarc_pass'] = True
    
    spf_status   = Fore.GREEN + "PASS ✅" if auth_results['spf_pass']   else Fore.RED + "FAIL ❌"
    dkim_status  = Fore.GREEN + "PASS ✅" if auth_results['dkim_pass']  else Fore.RED + "FAIL ❌"
    dmarc_status = Fore.GREEN + "PASS ✅" if auth_results['dmarc_pass'] else Fore.RED + "FAIL ❌"
    
    print(f"    SPF:   {spf_status}")
    print(f"    DKIM:  {dkim_status}")
    print(f"    DMARC: {dmarc_status}")
    
    return auth_results


def calculate_risk_score(auth_results, iocs, vt_results, abuse_results):
    """Calculate overall phishing risk score 0-100."""
    score = 0
    reasons = []
    
    # Authentication failures
    if not auth_results['spf_pass']:
        score += 20
        reasons.append("SPF check failed (+20)")
    if not auth_results['dkim_pass']:
        score += 15
        reasons.append("DKIM signature missing (+15)")
    if not auth_results['dmarc_pass']:
        score += 15
        reasons.append("DMARC check failed (+15)")
    
    # VirusTotal findings
    for ioc, result in vt_results.items():
        if isinstance(result, dict) and result.get('malicious', 0) > 0:
            score += min(result['malicious'] * 2, 20)
            reasons.append(f"VT flagged {ioc} as malicious (+{min(result['malicious']*2, 20)})")
    
    # AbuseIPDB findings
    for ip, result in abuse_results.items():
        if isinstance(result, dict):
            abuse_score = result.get('abuse_confidence_score', 0)
            if abuse_score > 50:
                score += 15
                reasons.append(f"IP {ip} has high abuse score: {abuse_score}% (+15)")
            elif abuse_score > 20:
                score += 8
                reasons.append(f"IP {ip} has moderate abuse score: {abuse_score}% (+8)")
    
    # Suspicious IOC count
    if len(iocs['urls']) > 5:
        score += 10
        reasons.append(f"High number of URLs: {len(iocs['urls'])} (+10)")
    
    score = min(score, 100)
    
    if score >= 75:
        risk_level = "🔴 CRITICAL"
    elif score >= 50:
        risk_level = "🟠 HIGH"
    elif score >= 25:
        risk_level = "🟡 MEDIUM"
    else:
        risk_level = "🟢 LOW"
    
    return score, risk_level, reasons


def run_threat_intel(iocs):
    """Run all threat intel lookups."""
    print(Fore.YELLOW + "\n[*] Running threat intelligence lookups...")
    
    vt_results    = {}
    abuse_results = {}
    
    # Check IPs
    for ip in iocs['ips'][:5]:  # limit to 5 to avoid API rate limits
        print(f"    Checking IP: {ip}")
        vt_results[ip]    = check_virustotal(ip, "ip")
        abuse_results[ip] = check_abuseipdb(ip)
    
    # Check URLs
    for url in iocs['urls'][:3]:  # limit to 3
        print(f"    Checking URL: {url[:50]}...")
        vt_results[url] = check_virustotal(url, "url")
    
    # Check domains
    for domain in iocs['domains'][:3]:  # limit to 3
        print(f"    Checking domain: {domain}")
        vt_results[domain] = check_virustotal(domain, "domain")
    
    return vt_results, abuse_results


def generate_report(headers, iocs, auth_results, vt_results, 
                    abuse_results, risk_score, risk_level, reasons):
    """Generate the final analysis report."""
    
    report = {
        "report_metadata": {
            "tool":           "Phishing Email Analyzer",
            "author":         "Your Name",
            "version":        "1.0",
            "analysis_date":  datetime.datetime.now().isoformat(),
            "mitre_technique": "T1566 - Phishing"
        },
        "email_headers": {
            "from":          headers['from'],
            "to":            headers['to'],
            "subject":       headers['subject'],
            "date":          headers['date'],
            "reply_to":      headers['reply_to'],
            "return_path":   headers['return_path'],
            "message_id":    headers['message_id'],
            "x_originating_ip": headers['x_originating']
        },
        "authentication": {
            "spf_pass":   auth_results['spf_pass'],
            "dkim_pass":  auth_results['dkim_pass'],
            "dmarc_pass": auth_results['dmarc_pass']
        },
        "iocs_extracted": {
            "ip_addresses": iocs['ips'],
            "urls":         iocs['urls'],
            "domains":      iocs['domains'],
            "total_iocs":   len(iocs['ips']) + len(iocs['urls']) + len(iocs['domains'])
        },
        "threat_intelligence": {
            "virustotal_results": vt_results,
            "abuseipdb_results":  abuse_results
        },
        "risk_assessment": {
            "risk_score":  risk_score,
            "risk_level":  risk_level,
            "score_breakdown": reasons,
            "verdict": "PHISHING DETECTED" if risk_score >= 50 else "LIKELY LEGITIMATE"
        }
    }
    
    return report


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Phishing Email Analyzer — IOC Extraction + Threat Intel'
    )
    parser.add_argument('email_file', help='Path to .eml file to analyze')
    parser.add_argument('--output', '-o', help='Output JSON file path', 
                        default='phishing_report.json')
    args = parser.parse_args()
    
    # Parse email
    headers, body = parse_email(args.email_file)
    
    # Print header summary
    print(Fore.CYAN + "\n📧 EMAIL SUMMARY")
    print(f"   From:    {headers['from']}")
    print(f"   To:      {headers['to']}")
    print(f"   Subject: {headers['subject']}")
    print(f"   Date:    {headers['date']}")
    
    # Extract IOCs
    iocs = extract_iocs(headers, body)
    
    # Analyze authentication
    auth_results = analyze_authentication(headers)
    
    # Run threat intel
    vt_results, abuse_results = run_threat_intel(iocs)
    
    # Calculate risk score
    risk_score, risk_level, reasons = calculate_risk_score(
        auth_results, iocs, vt_results, abuse_results
    )
    
    # Print risk score
    print(Fore.CYAN + "\n🎯 RISK ASSESSMENT")
    print(f"   Score:  {risk_score}/100")
    print(f"   Level:  {risk_level}")
    print(Fore.YELLOW + "\n   Score breakdown:")
    for reason in reasons:
        print(f"   → {reason}")
    
    verdict = "🚨 PHISHING DETECTED" if risk_score >= 50 else "✅ LIKELY LEGITIMATE"
    print(Fore.RED + f"\n   Verdict: {verdict}" if risk_score >= 50 
          else Fore.GREEN + f"\n   Verdict: {verdict}")
    
    # Generate report
    report = generate_report(
        headers, iocs, auth_results, 
        vt_results, abuse_results, 
        risk_score, risk_level, reasons
    )
    
    # Save report
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=4)
    
    print(Fore.GREEN + f"\n✅ Full report saved to: {args.output}")
    print(Fore.CYAN + "\n" + "="*55)


if __name__ == "__main__":
    main()
