import json
import urllib.request

TRIVY_REPORT = "vulnerability-report-v6.json"

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

print("\n===== CISA KEV SECURITY MONITOR =====\n")

print("[1] Downloading CISA KEV catalog...")

with urllib.request.urlopen(CISA_URL, timeout=30) as response:
    cisa_data = json.load(response)

kev_entries = cisa_data.get("vulnerabilities", [])

kev_cves = {
    item.get("cveID")
    for item in kev_entries
    if item.get("cveID")
}

print(f"[+] CISA KEV entries loaded: {len(kev_cves)}")

print("\n[2] Reading Trivy vulnerability report...")

with open(TRIVY_REPORT, "r", encoding="utf-8") as f:
    trivy_data = json.load(f)

matches = []

for result in trivy_data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        cve = vuln.get("VulnerabilityID")

        if cve in kev_cves:
            matches.append({
                "cve": cve,
                "package": vuln.get("PkgName"),
                "severity": vuln.get("Severity"),
                "installed": vuln.get("InstalledVersion"),
                "fixed": vuln.get("FixedVersion") or "Not available"
            })

print(f"[+] KEV matches found: {len(matches)}")

if matches:
    print("\n[!] KNOWN EXPLOITED VULNERABILITIES DETECTED\n")

    for item in matches:
        print(
            f"{item['cve']} | "
            f"{item['package']} | "
            f"{item['severity']} | "
            f"Installed: {item['installed']} | "
            f"Fix: {item['fixed']}"
        )

    print("\n[ACTION] Prioritize these vulnerabilities for remediation.")
else:
    print("\n[OK] No Trivy findings matched the CISA KEV catalog.")

print("\n===== CISA KEV CHECK COMPLETE =====")