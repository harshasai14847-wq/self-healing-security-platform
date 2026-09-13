import json
import re

REPORT_FILE = "vulnerability-report-all-v4.json"
REQUIREMENTS_FILE = "app/requirements.txt"


def version_tuple(version):
    numbers = re.findall(r"\d+", version)
    return tuple(int(x) for x in numbers)


def load_fixable_vulnerabilities():
    with open(REPORT_FILE, "r", encoding="utf-8") as f:
        report = json.load(f)

    fixes = {}

    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            package = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")

            if package and fixed:
                fixed_versions = [
                    x.strip() for x in fixed.split(",")
                    if x.strip()
                ]

                best_fix = min(
                    fixed_versions,
                    key=version_tuple
                )

                fixes[package.lower()] = {
                    "package": package,
                    "installed": installed,
                    "fixed": best_fix
                }

    return fixes


def update_requirements(fixes):
    with open(REQUIREMENTS_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    changed = False
    output = []

    for line in lines:
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            output.append(line)
            continue

        match = re.match(
            r"^([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9_.+-]*)",
            stripped
        )

        if not match:
            output.append(line)
            continue

        package = match.group(1)
        installed = match.group(2)

        fix = fixes.get(package.lower())

        if fix and version_tuple(fix["fixed"]) > version_tuple(installed):

            print(
                f"[AUTO-FIX] {package}: "
                f"{installed} -> {fix['fixed']}"
            )

            output.append(
                f"{package}=={fix['fixed']}\n"
            )

            changed = True

        else:
            output.append(line)

    if changed:
        with open(REQUIREMENTS_FILE, "w", encoding="utf-8") as f:
            f.writelines(output)

        print("\n[SUCCESS] requirements.txt updated automatically.")
    else:
        print("\n[INFO] No automatic dependency update required.")


def main():
    print("\n===== AUTOMATIC REMEDIATION ENGINE =====\n")

    fixes = load_fixable_vulnerabilities()

    print(f"Fixable packages discovered: {len(fixes)}")

    update_requirements(fixes)


if __name__ == "__main__":
    main()