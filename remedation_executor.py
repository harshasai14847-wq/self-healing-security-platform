import json
import subprocess
from pathlib import Path

REPORT = Path("vulnerability-report-v2.json")
PLAN = Path("remediation-plan.json")


def run_command(command):
    print(f"\n>>> {command}")
    result = subprocess.run(
        command,
        shell=True,
        text=True,
        capture_output=True
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    return result.returncode


def load_json(path):
    if not path.exists():
        print(f"[ERROR] File not found: {path}")
        return None

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    print("=" * 60)
    print("SELF-HEALING REMEDIATION EXECUTOR")
    print("=" * 60)

    report = load_json(REPORT)

    if report is None:
        return

    vulnerabilities = []

    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            vulnerabilities.append(vuln)

    print(f"\nTotal vulnerabilities detected: {len(vulnerabilities)}")

    high = [
        v for v in vulnerabilities
        if v.get("Severity") == "HIGH"
    ]

    critical = [
        v for v in vulnerabilities
        if v.get("Severity") == "CRITICAL"
    ]

    print(f"HIGH: {len(high)}")
    print(f"CRITICAL: {len(critical)}")

    print("\n--- REMEDIATION ANALYSIS ---")

    fix_available = []
    no_fix = []

    for vuln in vulnerabilities:
        fixed = vuln.get("FixedVersion")

        if fixed:
            fix_available.append(vuln)
        else:
            no_fix.append(vuln)

    print(f"Fix available: {len(fix_available)}")
    print(f"No fix available: {len(no_fix)}")

    print("\n--- FIXABLE VULNERABILITIES ---")

    for vuln in fix_available:
        print(
            f"{vuln.get('VulnerabilityID')} | "
            f"{vuln.get('PkgName')} | "
            f"{vuln.get('InstalledVersion')} -> "
            f"{vuln.get('FixedVersion')} | "
            f"{vuln.get('Severity')}"
        )

    print("\n--- NO-FIX VULNERABILITIES ---")

    for vuln in no_fix[:20]:
        print(
            f"{vuln.get('VulnerabilityID')} | "
            f"{vuln.get('PkgName')} | "
            f"{vuln.get('Severity')} | "
            f"NO_FIX_AVAILABLE"
        )

    print("\n" + "=" * 60)
    print("REMEDIATION DECISION")
    print("=" * 60)

    if not fix_available:
        print("\nNo automatically applicable package fixes were detected.")
        print("The system will NOT make unsafe changes.")
        print("No Docker rebuild performed.")
        return

    print(
        f"\n{len(fix_available)} vulnerabilities have "
        "a vendor-fixed version."
    )

    print(
        "\nNext stage would apply package updates "
        "and rebuild the Docker image."
    )


if __name__ == "__main__":
    main()