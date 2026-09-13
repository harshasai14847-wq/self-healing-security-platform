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


def calculate_priority(severity, known_exploited, fixed_version):
    severity = severity.upper()

    if known_exploited and severity == "CRITICAL":
        return "EMERGENCY"

    if known_exploited:
        return "CRITICAL"

    if severity == "CRITICAL" and fixed_version:
        return "HIGH"

    if severity == "CRITICAL":
        return "HIGH"

    if severity == "HIGH" and fixed_version:
        return "MEDIUM"

    if severity == "HIGH":
        return "LOW"

    return "MONITOR"


def main():
    kev_cves = load_kev()

    with open(TRIVY_REPORT, "r", encoding="utf-8") as f:
        report = json.load(f)

    priorities = {
        "EMERGENCY": 0,
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "MONITOR": 0
    }

    print("\n===== SELF-HEALING RISK PRIORITY ENGINE =====\n")

    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):

            cve = vuln.get("VulnerabilityID", "UNKNOWN")
            package = vuln.get("PkgName", "UNKNOWN")
            severity = vuln.get("Severity", "UNKNOWN")
            fixed = vuln.get("FixedVersion", "")

            known_exploited = cve in kev_cves

            priority = calculate_priority(
                severity,
                known_exploited,
                fixed
            )

            priorities[priority] += 1

            print(
                f"{cve} | "
                f"{severity} | "
                f"KEV={'YES' if known_exploited else 'NO'} | "
                f"Fix={'YES' if fixed else 'NO'} | "
                f"Priority={priority}"
            )

    print("\n===== PRIORITY SUMMARY =====")

    for level, count in priorities.items():
        print(f"{level}: {count}")


if __name__ == "__main__":
    main()