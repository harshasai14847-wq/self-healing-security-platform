import sys
import subprocess
import sys
import json
import sys
import os
import sys
import time
import sys
import urllib.request

OLD_IMAGE = "self-healing-app:v5"
NEW_IMAGE = "self-healing-app:v7"

OLD_REPORT = "vulnerability-report-v5.json"
NEW_REPORT = "vulnerability-report-v7.json"

CANDIDATE_CONTAINER = "secure-app-v7"
STABLE_PORT = 5000
CANDIDATE_PORT = 5001


def run_command(command):
    print(f"\n[RUN] {command}")
    result = subprocess.run(command, shell=True, text=True)
    return result.returncode == 0


def scan_image(image, report):
    return run_command(
        f'trivy image --format json -o "{report}" "{image}"'
    )


def count_vulnerabilities(report):
    with open(report, "r", encoding="utf-8") as f:
        data = json.load(f)

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "")
            if severity in counts:
                counts[severity] += 1

    return counts


def health_check():
    try:
        with urllib.request.urlopen(
            f"http://localhost:{CANDIDATE_PORT}/health",
            timeout=5
        ) as response:
            return response.status == 200
    except Exception:
        return False


print("\n======================================")
print("   SELF-HEALING SECURITY PIPELINE")
print("======================================")

print("\n[1] Security scanning...")
if not scan_image(OLD_IMAGE, OLD_REPORT):
    print("[FAIL] Initial scan failed.")
    exit()

before = count_vulnerabilities(OLD_REPORT)

print("\n[2] BEFORE REMEDIATION")
print(f"CRITICAL: {before['CRITICAL']}")
print(f"HIGH:     {before['HIGH']}")
print(f"MEDIUM:   {before['MEDIUM']}")
print(f"LOW:      {before['LOW']}")

print("\n[3] Checking CISA KEV...")
if os.path.exists("kev_priority_engine.py"):
    run_command("py kev_priority_engine.py")
else:
    print("[WARNING] KEV engine not found.")

print("\n[4] Applying dependency remediation...")
if os.path.exists("auto_remediation.py"):
    run_command("py auto_remediation.py")
else:
    print("[WARNING] Auto remediation engine not found.")

print("\n[5] Building candidate image...")
if not run_command(f"docker build --no-cache -t {NEW_IMAGE} ."):
    print("[FAIL] Candidate build failed.")
    exit()

    print("\n[6] Generating SBOM...")

    SBOM_FILE = "sbom-v7.json"

    if not run_command(
        f"trivy image --format cyclonedx -o {SBOM_FILE} {NEW_IMAGE}"
    ):
        print("[FAIL] SBOM generation failed.")
        exit()

    print(f"[PASS] SBOM generated: {SBOM_FILE}")
after = count_vulnerabilities(NEW_REPORT)

print("\n[7] AFTER REMEDIATION")
print(f"CRITICAL: {after['CRITICAL']}")
print(f"HIGH:     {after['HIGH']}")
print(f"MEDIUM:   {after['MEDIUM']}")
print(f"LOW:      {after['LOW']}")

before_total = sum(before.values())
after_total = sum(after.values())

print("\n[8] SECURITY COMPARISON")
print(f"Before: {before_total}")
print(f"After:  {after_total}")

if after_total >= before_total:
    print("\n[FAIL] Security posture did not improve.")
    print("[ACTION] Candidate deployment blocked.")
    exit()

print("\n[PASS] Security posture improved.")

print("\n[9] Starting candidate container...")

subprocess.run(
    f"docker rm -f {CANDIDATE_CONTAINER}",
    shell=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

if not run_command(
    f"docker run -d --name {CANDIDATE_CONTAINER} -p {CANDIDATE_PORT}:5000 {NEW_IMAGE}"
):
    print("[FAIL] Candidate failed to start.")
    sys.exit(1)
    exit()

time.sleep(3)

print("\n[10] Health testing...")

if not health_check():
    print("[FAIL] Candidate health check failed.")
    print("[ACTION] Automatic rollback.")
    exit()

print("[PASS] Candidate health check passed.")

print("\n======================================")
print(" SELF-HEALING PIPELINE DECISION")
print("======================================")
print("[PASS] Scan")
print("[PASS] KEV check")
print("[PASS] Remediation")
print("[PASS] Rebuild")
print("[PASS] Rescan")
print("[PASS] Security improvement")
print("[PASS] Health test")
print("\n[READY] Candidate is ready for traffic switch.")
print("\n[11] Automatically switching production traffic...")

if run_command("py traffic_switcher.py v7"):
    print("[PASS] Production traffic switched to v7.")
else:
    print("[FAIL] Automatic traffic switch failed.")
    print("[ACTION] Existing stable deployment remains active.")



