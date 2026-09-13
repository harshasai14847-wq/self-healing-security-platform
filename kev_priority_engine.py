import json
import urllib.request

TRIVY_REPORT = "vulnerability-report-v6.json"

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

print("\n===== KEV PRIORITY ENGINE =====\n")

# Load CISA KEV
with urllib.request.urlopen(CISA_URL, timeout=30) as response:
    cisa_data = json.load(response)

kev_cves = {
    item["cveID"]
    for item in cisa_data.get("vulnerabilities", [])
    if item.get("cveID")
}

print(f"[+] CISA KEV entries: {len(kev_cves)}")

# Load Trivy report
with open(TRIVY_REPORT, "r", encoding="utf-8") as f:
    report = json.load(f)

decisions = []

for result in report.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        cve = vuln.get("VulnerabilityID")
        severity = vuln.get("Severity", "")
        fixed = vuln.get("FixedVersion")

        if cve in kev_cves:
            action = "URGENT_REMEDIATE"
            priority = "P0"
        elif fixed and severity == "CRITICAL":
            action = "UPDATE_NOW"
            priority = "P1"
        elif fixed and severity == "HIGH":
            action = "UPDATE_PACKAGE"
            priority = "P2"
        elif fixed:
            action = "SCHEDULE_UPDATE"
            priority = "P3"
        else:
            action = "MONITOR"
            priority = "P4"

        decisions.append({
            "cve": cve,
            "package": vuln.get("PkgName"),
            "severity": severity,
            "installed": vuln.get("InstalledVersion"),
            "fixed": fixed or "Not available",
            "priority": priority,
            "action": action
        })

# Highest priority first
priority_order = {
    "P0": 0,
    "P1": 1,
    "P2": 2,
    "P3": 3,
    "P4": 4
}

decisions.sort(key=lambda x: priority_order[x["priority"]])

print("\n===== REMEDIATION DECISIONS =====\n")

for item in decisions:
    print(
        f"{item['priority']} | "
        f"{item['cve']} | "
        f"{item['package']} | "
        f"{item['severity']} | "
        f"{item['action']}"
    )

print(f"\n[+] Total decisions: {len(decisions)}")
print("\n===== KEV PRIORITY CHECK COMPLETE =====")