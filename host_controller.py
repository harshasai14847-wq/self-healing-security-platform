from flask import Flask, request, jsonify
import subprocess
import json
import os
import re
from datetime import datetime

app = Flask(__name__)

BASE_DIR = r"D:\self-healing-app"
REPORT_DIR = BASE_DIR

print("\n======================================")
print("       HOST SECURITY CONTROLLER")
print("======================================\n")


def safe_name(name):
    """Create a safe filename from the application name."""
    name = name.strip()
    name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
    return name[:80] or "application"


def run_command(command):
    """Run a command and return result."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300
        )

        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    except subprocess.TimeoutExpired:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "Command timed out."
        }

    except Exception as error:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(error)
        }


def docker_image_exists(image):
    result = run_command([
        "docker",
        "image",
        "inspect",
        image
    ])

    return result["returncode"] == 0


def pull_docker_image(image):
    print(f"[INFO] Image not found locally: {image}")
    print("[INFO] Attempting to pull image...")

    result = run_command([
        "docker",
        "pull",
        image
    ])

    return result


def scan_image(image, report_file):
    print(f"[INFO] Running Trivy scan on: {image}")

    result = run_command([
        "trivy",
        "image",
        "--format",
        "json",
        "--output",
        report_file,
        image
    ])

    return result


def count_vulnerabilities(report_file):
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    if not os.path.exists(report_file):
        return counts

    try:
        with open(report_file, "r", encoding="utf-8") as file:
            data = json.load(file)

        for result in data.get("Results", []):
            for vulnerability in result.get("Vulnerabilities", []):
                severity = vulnerability.get("Severity", "").upper()

                if severity in counts:
                    counts[severity] += 1

    except Exception as error:
        print(f"[ERROR] Could not read Trivy report: {error}")

    return counts


@app.route("/")
def home():
    return jsonify({
        "service": "Self-Healing Security Controller",
        "status": "online",
        "port": 5051
    })


@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "host-controller"
    })


@app.route("/scan", methods=["POST"])
def scan_application():

    app_name = request.form.get("app_name", "").strip()
    docker_image = request.form.get("docker_image", "").strip()

    # Also accept JSON requests
    if not app_name or not docker_image:
        data = request.get_json(silent=True) or {}

        app_name = app_name or str(data.get("app_name", "")).strip()
        docker_image = docker_image or str(data.get("docker_image", "")).strip()

    print("\n======================================")
    print("        NEW APPLICATION SCAN")
    print("======================================")
    print(f"[+] Application : {app_name}")
    print(f"[+] Docker Image: {docker_image}")

    if not app_name or not docker_image:
        return jsonify({
            "status": "error",
            "message": "Application name and Docker image are required."
        }), 400

    safe_app_name = safe_name(app_name)

    report_file = os.path.join(
        REPORT_DIR,
        f"{safe_app_name}_trivy_report.json"
    )

    # ------------------------------------------------
    # STEP 1: Check Docker image
    # ------------------------------------------------

    print("\n[1] Checking Docker image...")

    if not docker_image_exists(docker_image):

        print("[INFO] Docker image not available locally.")

        pull_result = pull_docker_image(docker_image)

        if pull_result["returncode"] != 0:
            print("[ERROR] Could not pull Docker image.")

            return jsonify({
                "status": "error",
                "message": "Docker image was not found locally and could not be pulled.",
                "docker_image": docker_image,
                "details": pull_result["stderr"]
            }), 400

    print("[PASS] Docker image available.")

    # ------------------------------------------------
    # STEP 2: Trivy security scan
    # ------------------------------------------------

    print("\n[2] Starting security scan...")

    scan_result = scan_image(
        docker_image,
        report_file
    )

    if scan_result["returncode"] != 0:

        print("[ERROR] Trivy scan failed.")

        return jsonify({
            "status": "error",
            "message": "Trivy security scan failed.",
            "details": scan_result["stderr"]
        }), 500

    print("[PASS] Security scan completed.")

    # ------------------------------------------------
    # STEP 3: Analyze vulnerabilities
    # ------------------------------------------------

    print("\n[3] Analyzing vulnerabilities...")

    counts = count_vulnerabilities(report_file)

    total = sum(counts.values())

    print(f"[+] CRITICAL: {counts['CRITICAL']}")
    print(f"[+] HIGH:     {counts['HIGH']}")
    print(f"[+] MEDIUM:   {counts['MEDIUM']}")
    print(f"[+] LOW:      {counts['LOW']}")
    print(f"[+] TOTAL:    {total}")

    # ------------------------------------------------
    # STEP 4: Security decision
    # ------------------------------------------------

    if counts["CRITICAL"] > 0:
        decision = "CRITICAL_REMEDIATION_REQUIRED"
        security_status = "CRITICAL"

    elif counts["HIGH"] > 0:
        decision = "HIGH_RISK_REMEDIATION_REQUIRED"
        security_status = "HIGH"

    elif counts["MEDIUM"] > 0:
        decision = "MEDIUM_RISK"
        security_status = "MEDIUM"

    else:
        decision = "SECURE"
        security_status = "SECURE"

    # ------------------------------------------------
    # STEP 5: Save application information
    # ------------------------------------------------

    application_record = {
        "application_name": app_name,
        "docker_image": docker_image,
        "scan_time": datetime.now().isoformat(),
        "report_file": report_file,
        "vulnerabilities": counts,
        "total_findings": total,
        "security_status": security_status,
        "decision": decision
    }

    record_file = os.path.join(
        REPORT_DIR,
        f"{safe_app_name}_application.json"
    )

    with open(
        record_file,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            application_record,
            file,
            indent=4
        )

    print("\n======================================")
    print("          SCAN COMPLETED")
    print("======================================")
    print(f"[+] Application : {app_name}")
    print(f"[+] Image       : {docker_image}")
    print(f"[+] Total       : {total}")
    print(f"[+] Status      : {security_status}")
    print(f"[+] Decision    : {decision}")
    print("======================================\n")

    return jsonify({
        "status": "success",
        "application": application_record
    })


if __name__ == "__main__":

    print("Listening on port 5051")
    print("Controller URL: http://127.0.0.1:5051")
    print("Scan endpoint : http://127.0.0.1:5051/scan")
    print()

    app.run(
        host="0.0.0.0",
        port=5051,
        debug=False
    )
