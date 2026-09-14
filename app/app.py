from flask import Flask, render_template, request, redirect
import json
import os
import urllib.request
import urllib.parse

app = Flask(__name__)

# Dashboard runs inside Docker, so use its own /app directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

HOST_CONTROLLER = "http://127.0.0.1:5051/scan"

RESULT_FILE = os.path.join(
    BASE_DIR,
    "latest_application_result.json"
)


def get_latest_result():

    if not os.path.exists(RESULT_FILE):
        return {
            "application_name": "",
            "docker_image": "",
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "TOTAL": 0,
            "security_status": "NO APPLICATION SCANNED",
            "decision": "WAITING"
        }

    try:
        with open(
            RESULT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception as error:

        print(f"[ERROR] Could not read result: {error}")

        return {
            "application_name": "",
            "docker_image": "",
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "TOTAL": 0,
            "security_status": "ERROR",
            "decision": "ERROR"
        }


@app.route("/")
def dashboard():

    result = get_latest_result()

    return render_template(
        "dashboard.html",

        critical=result.get("CRITICAL", 0),
        high=result.get("HIGH", 0),
        medium=result.get("MEDIUM", 0),
        low=result.get("LOW", 0),

        total=result.get("TOTAL", 0),

        application_name=result.get(
            "application_name",
            ""
        ),

        docker_image=result.get(
            "docker_image",
            ""
        ),

        security_status=result.get(
            "security_status",
            "NO APPLICATION SCANNED"
        ),

        decision=result.get(
            "decision",
            "WAITING"
        )
    )


@app.route(
    "/add-application",
    methods=["POST"]
)
def add_application():

    app_name = request.form.get(
        "app_name",
        ""
    ).strip()

    docker_image = request.form.get(
        "docker_image",
        ""
    ).strip()

    print("\n======================================")
    print("       APPLICATION SUBMISSION")
    print("======================================")

    print(f"Application: {app_name}")
    print(f"Docker Image: {docker_image}")

    if not app_name or not docker_image:

        print(
            "[ERROR] Application name and Docker image are required."
        )

        return redirect("/")

    try:

        print(
            "[INFO] Sending application to Host Security Controller..."
        )

        data = urllib.parse.urlencode({

            "app_name": app_name,

            "docker_image": docker_image

        }).encode("utf-8")

        request_object = urllib.request.Request(

            HOST_CONTROLLER,

            data=data,

            method="POST"
        )

        with urllib.request.urlopen(
            request_object,
            timeout=300
        ) as response:

            response_data = (
                response
                .read()
                .decode("utf-8")
            )

        print(
            "[PASS] Host Security Controller completed."
        )

        result = json.loads(
            response_data
        )

        print(
            json.dumps(
                result,
                indent=4
            )
        )

        application_data = result.get(
            "application",
            {}
        )

        vulnerabilities = application_data.get(
            "vulnerabilities",
            {}
        )

        dashboard_result = {

            "application_name": app_name,

            "docker_image": docker_image,

            "CRITICAL": vulnerabilities.get(
                "CRITICAL",
                0
            ),

            "HIGH": vulnerabilities.get(
                "HIGH",
                0
            ),

            "MEDIUM": vulnerabilities.get(
                "MEDIUM",
                0
            ),

            "LOW": vulnerabilities.get(
                "LOW",
                0
            ),

            "TOTAL": application_data.get(
                "total_findings",
                0
            ),

            "security_status": application_data.get(
                "security_status",
                "UNKNOWN"
            ),

            "decision": application_data.get(
                "decision",
                "UNKNOWN"
            )
        }

        with open(
            RESULT_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                dashboard_result,
                file,
                indent=4
            )

        print(
            "[PASS] Dashboard result saved."
        )

    except Exception as error:

        print(
            f"[ERROR] Scan failed: {error}"
        )

    return redirect("/")


@app.route("/health")
def health():

    return "OK", 200


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
