import json
from datetime import datetime

TRIVY_REPORT = "vulnerability-report-v3.json"
KEV_FILE = "cisa_kev.json"


def load_json(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return json.load(f)


def load_kev():
    data = load_json(KEV_FILE)

    return {
        item["cveID"]
        for item in data.get("vulnerabilities", [])
    }


def analyze():
    report = load_json(TRIVY_REPORT)
    kev_cves = load_kev()

    findings = []

    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):

            cve = vuln.get("VulnerabilityID", "UNKNOWN")
            severity = vuln.get("Severity", "UNKNOWN").upper()
            fixed = vuln.get("FixedVersion", "")

            known_exploited = cve in kev_cves

            if known_exploited:
                priority = "EMERGENCY"
                action = "REMEDIATE_NOW"

            elif severity == "CRITICAL" and fixed:
                priority = "HIGH"
                action = "REMEDIATE"

            elif severity == "CRITICAL" and not fixed:
                priority = "HIGH"
                action = "MONITOR_NO_FIX"

            elif severity == "HIGH" and fixed:
                priority = "MEDIUM"
                action = "REMEDIATE"

            elif severity == "HIGH" and not fixed:
                priority = "LOW"
                action = "MONITOR_NO_FIX"

            else:
                priority = "MONITOR"
                action = "MONITOR"

            findings.append({
                "cve": cve,
                "package": vuln.get("PkgName", "UNKNOWN"),
                "severity": severity,
                "fixed_version": fixed or "Not available",
                "known_exploited": known_exploited,
                "priority": priority,
                "action": action
            })

    return findings


def main():

    print("\n==========================================")
    print("       SELF-HEALING SECURITY CONTROLLER")
    print("==========================================\n")

    findings = analyze()

    emergency = sum(
        1 for x in findings if x["priority"] == "EMERGENCY"
    )

    remediation = sum(
        1 for x in findings
        if x["action"] in ["REMEDIATE", "REMEDIATE_NOW"]
    )

    no_fix = sum(
        1 for x in findings
        if x["action"] == "MONITOR_NO_FIX"
    )

    print(f"Total vulnerabilities : {len(findings)}")
    print(f"Emergency threats    : {emergency}")
    print(f"Remediation possible : {remediation}")
    print(f"No-fix findings      : {no_fix}")

    print("\n===== SYSTEM DECISION =====\n")

    if emergency > 0:
        print("[EMERGENCY]")
        print("Known exploited vulnerability detected.")
        print("Immediate remediation required.")

    elif remediation > 0:
        print("[REMEDIATE]")
        print("Vulnerabilities with available fixes detected.")
        print("Safe remediation can be attempted.")

    elif no_fix > 0:
        print("[MONITOR]")
        print("Vulnerabilities detected without available fixes.")
        print("System will not perform unsafe changes.")

    else:
        print("[SECURE]")
        print("No actionable vulnerabilities detected.")

    output = {
        "timestamp": datetime.now().isoformat(),
        "total_vulnerabilities": len(findings),
        "emergency": emergency,
        "remediation_possible": remediation,
        "no_fix": no_fix,
        "findings": findings
    }

    with open("security_decision.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("\nDecision saved to: security_decision.json")


if __name__ == "__main__":
    main()