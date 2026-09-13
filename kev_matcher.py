import json

TRIVY_REPORT = "vulnerability-report-v3.json"
KEV_FILE = "cisa_kev.json"


def load_kev():
    with open(KEV_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    return {
        item["cveID"]
        for item in data.get("vulnerabilities", [])
    }


def check_vulnerabilities():
    kev_cves = load_kev()

    with open(TRIVY_REPORT, "r", encoding="utf-8") as f:
        report = json.load(f)

    findings = []

    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve = vuln.get("VulnerabilityID", "UNKNOWN")

            findings.append({
                "cve": cve,
                "package": vuln.get("PkgName", "UNKNOWN"),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "fixed": vuln.get("FixedVersion", ""),
                "known_exploited": cve in kev_cves
            })

    return findings


if __name__ == "__main__":
    findings = check_vulnerabilities()

    kev_count = 0

    print("\n===== CISA KEV THREAT ANALYSIS =====\n")

    for item in findings:
        if item["known_exploited"]:
            kev_count += 1

            print("[KNOWN EXPLOITED]")
            print(f"  CVE:      {item['cve']}")
            print(f"  Package:  {item['package']}")
            print(f"  Severity: {item['severity']}")
            print(f"  Fix:      {item['fixed'] or 'Not available'}")
            print()

    print("------------------------------------")
    print(f"Total Trivy findings: {len(findings)}")
    print(f"CISA KEV matches:    {kev_count}")
    print("------------------------------------")