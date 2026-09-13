import urllib.request
import subprocess
import time

CANDIDATE_PORT = 5001
STABLE_PORT = 5000

NGINX_CONFIG = "nginx.conf"


def health_check(port):
    try:
        url = f"http://localhost:{port}/health"
        response = urllib.request.urlopen(url, timeout=3)

        if response.status == 200:
            return True

    except Exception:
        return False

    return False


def switch_traffic(port):
    with open(NGINX_CONFIG, "r", encoding="utf-8") as file:
        config = file.read()

    if "server host.docker.internal:5001;" in config:
        config = config.replace(
            "server host.docker.internal:5001;",
            f"server host.docker.internal:{port};"
        )

    elif "server host.docker.internal:5000;" in config:
        config = config.replace(
            "server host.docker.internal:5000;",
            f"server host.docker.internal:{port};"
        )

    with open(NGINX_CONFIG, "w", encoding="utf-8") as file:
        file.write(config)

    subprocess.run(
        [
            "docker",
            "restart",
            "traffic-router"
        ],
        check=True
    )


print("\n===== SELF-HEALING AUTOMATIC ROLLBACK =====\n")

print("[1] Checking candidate application...")
print(f"[+] Candidate: port {CANDIDATE_PORT}")

time.sleep(1)

if health_check(CANDIDATE_PORT):

    print("[PASS] Candidate health check passed.")
    print("[+] Candidate is healthy.")
    print("[+] Keeping traffic on candidate.")
    switch_traffic(CANDIDATE_PORT)

    print("[SUCCESS] Traffic remains on candidate.")

else:

    print("[FAIL] Candidate health check failed!")
    print("[!] Automatic rollback triggered.")
    print(f"[+] Switching traffic back to stable port {STABLE_PORT}...")

    switch_traffic(STABLE_PORT)

    print("[SUCCESS] Traffic rolled back to stable application.")

print("\n===== ROLLBACK CHECK COMPLETE =====\n")