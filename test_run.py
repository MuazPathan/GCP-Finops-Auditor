import os
from scanner import GCPHygieneScanner, HygieneReportGenerator

# Configured to your active project
PROJECT_ID = "project-bed96318-a366-415d-806"

def main():
    print(f"\n--- Running Cloud Hygiene Scanner on: {PROJECT_ID} ---\n")
    scanner = GCPHygieneScanner(project_id=PROJECT_ID)
    findings = scanner.run_all_scans()
    
    report_md = HygieneReportGenerator.to_markdown(PROJECT_ID, findings)
    print(report_md)
    
    # Save a copy as JSON
    report_json = HygieneReportGenerator.to_json(PROJECT_ID, findings)
    with open("hygiene_audit_results.json", "w") as f:
        f.write(report_json)
    print("\nSaved full audit data to: hygiene_audit_results.json")

if __name__ == "__main__":
    main()