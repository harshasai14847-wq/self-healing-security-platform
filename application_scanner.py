import json
import subprocess
import os
from datetime import datetime

REGISTRATION_FILE = "registered_application.json"


def run_command(command):
    print("\n[RUN]", " ".join(command))

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.stdout:
        print(result.stdout)

    if result.returncode != 0:
        if result.stderr:
            print(result.stderr)
        return False

    return True


def main():

    print("\n==============================================")
    print("       SELF-HEALING APPLICATION SCANNER")
    print("==============================================")

    if not os.path.exists(REGISTRATION_FILE):
        print("[ERROR] No application has been registered.")
        print("[INFO] Submit an application from the dashboard first.")
        return

    with open(REGISTRATION_FILE, "r", encoding="utf-8") as file:
        application = json.load(file)

    app_name = application.get("application")
    docker_image = application.get("docker_image")

    print(f"\nApplication : {app_name}")
    print(f"Docker Image: {docker_image}")

    print("\n[1] Checking Docker image...")

    check = subprocess.run(
        ["docker", "image", "inspect", docker_image],
        capture_output=True,
        text=True
    )

    if check.returncode != 0:

        print("[INFO] Image not found locally.")
        print("[INFO] Attempting Docker pull...")

        if not run_command(["docker", "pull", docker_image]):
            print("[FAIL] Could not obtain Docker image.")
            return

    print("[PASS] Docker image available.")

    safe_name = "".join(
        c if c.isalnum() or c in "-_"
        else "_"
        for c in app_name
    )

    report_file = f"{safe_name}_security_report.json"

    print("\n[2] Running Trivy security scan...")

    if not run_command([
        "trivy",
        "image",
        "--format",
        "json",
        "-o",
        report_file,
        docker_image
    ]):
        print("[FAIL] Trivy scan failed.")
        return

    print(f"[PASS] Security report created: {report_file}")

    print("\n[3] Analyzing vulnerabilities...")

    try:

        with open(report_file, "r", encoding="utf-8") as file:
            report = json.load(file)

        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for result in report.get("Results", []):

            for vulnerability in result.get(
                "Vulnerabilities", []
            ):

                severity = vulnerability.get(
                    "Severity",
                    ""
                ).upper()

                if severity in counts:
                    counts[severity] += 1

        print("\n========== SECURITY RESULT ==========")

        print(
            f"CRITICAL : {counts['CRITICAL']}"
        )

        print(
            f"HIGH     : {counts['HIGH']}"
        )

        print(
            f"MEDIUM   : {counts['MEDIUM']}"
        )

        print(
            f"LOW      : {counts['LOW']}"
        )

        total = sum(counts.values())

        print(
            f"TOTAL    : {total}"
        )

        print("=====================================")

    except Exception as error:

        print(
            f"[ERROR] Could not analyze report: {error}"
        )

        return

    print("\n[4] Security decision...")

    if counts["CRITICAL"] > 0:

        print(
            "[ALERT] CRITICAL vulnerabilities detected."
        )

        print(
            "[ACTION] Remediation required."
        )

    elif counts["HIGH"] > 0:

        print(
            "[WARNING] HIGH vulnerabilities detected."
        )

        print(
            "[ACTION] Remediation required."
        )

    else:

        print(
            "[PASS] No HIGH or CRITICAL vulnerabilities."
        )

    print("\n==============================================")
    print("           APPLICATION SCAN COMPLETE")
    print("==============================================")

    result = {
        "application": app_name,
        "docker_image": docker_image,
        "scan_time": datetime.now().isoformat(),
        "vulnerabilities": counts,
        "total": total
    }

    with open(
        "latest_application_result.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            result,
            file,
            indent=4
        )

    print(
        "[PASS] Latest result saved."
    )


if __name__ == "__main__":
    main()