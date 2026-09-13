import os
import shutil
import subprocess
from datetime import datetime

DOCKERFILE = "Dockerfile"
IMAGE_NAME = "self-healing-app:v2"
BACKUP = "Dockerfile.backup"


def backup_dockerfile():
    if not os.path.exists(DOCKERFILE):
        print("ERROR: Dockerfile not found.")
        return False

    shutil.copy2(DOCKERFILE, BACKUP)
    print(f"Backup created: {BACKUP}")
    return True


def add_security_update():
    with open(DOCKERFILE, "r", encoding="utf-8") as file:
        content = file.read()

    if "apt-get upgrade" in content:
        print("Security update already exists in Dockerfile.")
        return False

    update_command = """
RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*
"""

    with open(DOCKERFILE, "a", encoding="utf-8") as file:
        file.write("\n" + update_command)

    print("Security update added to Dockerfile.")
    return True


def rebuild_image():
    print("\n=== REBUILDING SECURE IMAGE ===\n")

    result = subprocess.run(
        ["docker", "build", "-t", IMAGE_NAME, "."],
        text=True
    )

    return result.returncode == 0


def scan_image():
    print("\n=== RUNNING TRIVY RESCAN ===\n")

    result = subprocess.run(
        [
            "trivy",
            "image",
            "--severity", "HIGH,CRITICAL",
            "--format", "json",
            "--output", "vulnerability-report-v2.json",
            IMAGE_NAME
        ],
        text=True
    )

    return result.returncode == 0


if __name__ == "__main__":

    print("\n=== SELF-HEALING REMEDIATION EXECUTOR ===\n")

    if not backup_dockerfile():
        exit(1)

    changed = add_security_update()

    if not changed:
        print("No Dockerfile change required.")
        exit(0)

    if not rebuild_image():
        print("\nERROR: Docker rebuild failed.")
        print(f"Restore backup with: Copy-Item {BACKUP} {DOCKERFILE} -Force")
        exit(1)

    print("\nDocker image rebuilt successfully.")

    if scan_image():
        print("\nRescan completed.")
        print("Report: vulnerability-report-v2.json")
    else:
        print("\nTrivy rescan failed.")
        print("The rebuilt image still exists; investigate before deployment.")