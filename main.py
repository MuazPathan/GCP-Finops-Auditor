import json
import os
import requests
from flask import Flask, jsonify, request
from scanner import GCPHygieneScanner, HygieneReportGenerator

app = Flask(__name__)

@app.route("/", methods=["POST", "GET"])
def trigger_scan():
    project_id = os.environ.get("GCP_PROJECT_ID", "project-bed96318-a366-415d-806")
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    scanner = GCPHygieneScanner(project_id=project_id)
    findings = scanner.run_all_scans()

    json_report = HygieneReportGenerator.to_json(project_id, findings)
    markdown_report = HygieneReportGenerator.to_markdown(project_id, findings)

    if webhook_url:
        try:
            requests.post(
                webhook_url,
                json={"text": f"Cloud Hygiene Scan for `{project_id}`", "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": markdown_report[:2900]}}]},
                timeout=10
            )
        except Exception as e:
            app.logger.warning(f"Webhook alert failed: {e}")

    return jsonify({
        "status": "COMPLETED",
        "project_id": project_id,
        "findings_count": len(findings),
        "report": json.loads(json_report)
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))