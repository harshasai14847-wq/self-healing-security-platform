import json

REPORT_FILE = "vulnerability-report.json"


def load_report():
    with open(REPORT_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def choose_action(vulnerability):
    severity = vulnerability.get("Severity", "").upper()
    package = vulnerability.get("PkgName", "")
    fixed_version = vulnerability.get("FixedVersion", "")

    if severity == "CRITICAL":
        action = "URGENT_UPDATE"

    elif severity == "HIGH":
        action = "UPDATE_PACKAGE"

    elif severity == "MEDIUM":
        action = "PLAN_UPDATE"

    else:
        action = "MONITOR"

    if not fixed_version:
        action = "NO_FIX_AVAILABLE"

    return {
        "package": package,
        "severity": severity,
        "fixed_version": fixed_version or "Not available",
        "action": action
    }


def analyze():
    report = load_report()

    results = []

    for target in report.get("Results", []):
        for vulnerability in target.get("Vulnerabilities", []):
            results.append(choose_action(vulnerability))

    return results


if __name__ == "__main__":
    decisions = analyze()

    print("\n=== SELF-HEALING REMEDIATION ENGINE ===\n")

    for item in decisions:
        print(
            f"[{item['severity']}] "
            f"{item['package']} -> "
            f"{item['action']} "
            f"(Fix: {item['fixed_version']})"
        )

    print(f"\nTotal vulnerabilities analyzed: {len(decisions)}")