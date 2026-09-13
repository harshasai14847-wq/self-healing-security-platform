import json

REPORT = "vulnerability-report.json"

with open(REPORT, "r", encoding="utf-8") as f:
    data = json.load(f)

high = []
critical = []

for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        severity = vuln.get("Severity", "")
        
        item = {
            "id": vuln.get("VulnerabilityID", "Unknown"),
            "package": vuln.get("PkgName", "Unknown"),
            "installed": vuln.get("InstalledVersion", "Unknown"),
            "fixed": vuln.get("FixedVersion", "Not available")
        }

        if severity == "CRITICAL":
            critical.append(item)
        elif severity == "HIGH":
            high.append(item)

print("\n===== SELF-HEALING SECURITY ANALYZER =====\n")

print(f"CRITICAL vulnerabilities: {len(critical)}")
print(f"HIGH vulnerabilities:     {len(high)}")

if critical or high:
    print("\n[!] SECURITY PROBLEM DETECTED")
    print("[!] Remediation is required.\n")

    for item in critical:
        print(f"[CRITICAL] {item['id']}")
        print(f"  Package: {item['package']}")
        print(f"  Installed: {item['installed']}")
        print(f"  Fixed: {item['fixed']}\n")

    for item in high:
        print(f"[HIGH] {item['id']}")
        print(f"  Package: {item['package']}")
        print(f"  Installed: {item['installed']}")
        print(f"  Fixed: {item['fixed']}\n")
else:
    print("[OK] No HIGH or CRITICAL vulnerabilities detected.")