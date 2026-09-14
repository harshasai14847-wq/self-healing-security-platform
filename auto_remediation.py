import json
import glob
import os
import re

REPORT_FILE = ""
REQUIREMENTS_FILE = "app/requirements.txt"
DOCKERFILE = "Dockerfile"


def load_report():
    if not os.path.exists(REPORT_FILE):
        reports = glob.glob("vulnerability-report*.json")
        reports = [r for r in reports if "vulnerability-report" in r]

        if not reports:
            print("[ERROR] No Trivy report found.")
            return {}

        REPORT = max(reports, key=os.path.getmtime)
    else:
        REPORT = REPORT_FILE

    print(f"[INFO] Reading report: {REPORT}")

    with open(REPORT, "r", encoding="utf-8") as f:
        return json.load(f)


def find_fixes(data):
    fixes = {}

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            package = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")

            if package and fixed:
                if package not in fixes:
                    fixes[package] = {
                        "installed": installed,
                        "fixed": fixed
                    }

    return fixes


def update_requirements(fixes):
    if not os.path.exists(REQUIREMENTS_FILE):
        print("[INFO] requirements.txt not found.")
        return False

    with open(REQUIREMENTS_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    changed = False
    output = []

    python_packages = {
        "flask": "Flask",
        "werkzeug": "Werkzeug"
    }

    for line in lines:
        stripped = line.strip()
        updated = False

        for key, display_name in python_packages.items():
            pattern = rf"^{re.escape(display_name)}(\s*==\s*.*)?$"

            if re.match(pattern, stripped, re.IGNORECASE):
                if key in fixes:
                    fixed = fixes[key]["fixed"]
                    output.append(f"{display_name}=={fixed}\n")
                    print(
                        f"[AUTO-FIX] {display_name}: "
                        f"{fixes[key]['installed']} -> {fixed}"
                    )
                    changed = True
                    updated = True

        if not updated:
            output.append(line)

    if changed:
        with open(REQUIREMENTS_FILE, "w", encoding="utf-8") as f:
            f.writelines(output)

        print("[SUCCESS] requirements.txt updated automatically.")

    return changed


def update_dockerfile(fixes):
    if not os.path.exists(DOCKERFILE):
        print("[INFO] Dockerfile not found.")
        return False

    with open(DOCKERFILE, "r", encoding="utf-8") as f:
        content = f.read()

    if "python -m pip install --upgrade pip" in content:
        return False

    if "pip" not in fixes:
        return False

    marker = "WORKDIR /app"

    if marker not in content:
        print("[WARNING] Could not find WORKDIR in Dockerfile.")
        return False

    new_line = (
        "\n"
        "# Automatically remediate fixable pip vulnerabilities\n"
        "RUN python -m pip install --no-cache-dir --upgrade pip\n"
    )

    content = content.replace(
        marker,
        marker + new_line,
        1
    )

    with open(DOCKERFILE, "w", encoding="utf-8") as f:
        f.write(content)

    print(
        f"[AUTO-FIX] pip: "
        f"{fixes['pip']['installed']} -> "
        f"{fixes['pip']['fixed']}"
    )

    print("[SUCCESS] Dockerfile updated for pip remediation.")

    return True


def main():
    print("\n===== AUTOMATIC REMEDIATION ENGINE =====\n")

    data = load_report()

    if not data:
        return

    fixes = find_fixes(data)

    print(f"Fixable packages discovered: {len(fixes)}")

    if not fixes:
        print("[INFO] No fixable vulnerabilities found.")
        return

    print("\n[FIXES DISCOVERED]")

    for package, info in fixes.items():
        print(
            f"  {package}: "
            f"{info['installed']} -> {info['fixed']}"
        )

    print("\n[1] Updating Python dependencies...")
    requirements_changed = update_requirements(fixes)

    print("\n[2] Updating pip in Dockerfile...")
    dockerfile_changed = update_dockerfile(fixes)

    print("\n===== REMEDIATION RESULT =====")

    if requirements_changed or dockerfile_changed:
        print("[SUCCESS] Automatic remediation changes applied.")
        print("[NEXT] Rebuild the Docker image and run Trivy again.")
    else:
        print("[INFO] No new remediation changes were required.")


if __name__ == "__main__":
    main()
