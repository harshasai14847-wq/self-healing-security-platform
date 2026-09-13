import json

REPORT_FILE = "vulnerability-report.json"


def create_plan():
    with open(REPORT_FILE, "r", encoding="utf-8") as file:
        report = json.load(file)

    plan = []

    for target in report.get("Results", []):
        for vuln in target.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "").upper()
            package = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")

            if fixed:
                if severity == "CRITICAL":
                    action = "UPDATE_NOW"
                elif severity == "HIGH":
                    action = "UPDATE_PACKAGE"
                elif severity == "MEDIUM":
                    action = "SCHEDULE_UPDATE"
                else:
                    action = "MONITOR"
            else:
                action = "NO_FIX_AVAILABLE"

            plan.append({
                "id": vuln.get("VulnerabilityID", "UNKNOWN"),
                "package": package,
                "installed_version": installed,
                "fixed_version": fixed or "Not available",
                "severity": severity,
                "action": action
            })

    return plan


if __name__ == "__main__":
    plan = create_plan()

    print("\n=== SELF-HEALING REMEDIATION PLAN ===\n")

    for item in plan:
        print(
            f"{item['id']} | "
            f"{item['package']} | "
            f"{item['severity']} | "
            f"{item['action']} | "
            f"Fix: {item['fixed_version']}"
        )

    print(f"\nTotal remediation decisions: {len(plan)}")