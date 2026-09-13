import subprocess
import sys

NGINX_CONFIG = "nginx.conf"
ROUTER = "traffic-router"


def switch_traffic(port):
    print(f"[SWITCH] Changing traffic target to port {port}...")

    try:
        with open(NGINX_CONFIG, "r", encoding="utf-8") as file:
            config = file.read()

        lines = config.splitlines()
        new_lines = []

        for line in lines:
            if "server host.docker.internal:" in line:
                new_lines.append(
                    f"        server host.docker.internal:{port};"
                )
            else:
                new_lines.append(line)

        with open(NGINX_CONFIG, "w", encoding="utf-8") as file:
            file.write("\n".join(new_lines) + "\n")

        print(f"[PASS] Traffic target changed to port {port}")

        subprocess.run(
            ["docker", "restart", ROUTER],
            check=True
        )

        print("[PASS] Traffic router restarted.")
        return True

    except Exception as error:
        print(f"[FAIL] Traffic switch failed: {error}")
        return False


if __name__ == "__main__":

    if len(sys.argv) > 1:

        target = sys.argv[1].lower()

        if target == "v5":
            switch_traffic(5000)

        elif target == "v7":
            switch_traffic(5001)

        elif target == "v8":
            switch_traffic(5002)

        else:
            print("[ERROR] Unknown target.")
            print("[INFO] Use: v5, v7, or v8")

    else:

        print("===== AUTOMATIC TRAFFIC SWITCHER =====")
        print("1. Switch to v5 (port 5000)")
        print("2. Switch to v7 (port 5001)")
        print("3. Switch to v8 Dashboard (port 5002)")

        choice = input("Choose target (1/2/3): ").strip()

        if choice == "1":
            switch_traffic(5000)

        elif choice == "2":
            switch_traffic(5001)

        elif choice == "3":
            switch_traffic(5002)

        else:
            print("[ERROR] Invalid choice.")