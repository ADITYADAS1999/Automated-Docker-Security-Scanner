import json
import os

# Folder where JSON reports are stored
REPORTS_DIR = "reports"
OUTPUT_FILE = os.path.join(REPORTS_DIR, "nist_report.json")

# NIST CSF categories
CSF_CATEGORIES = {
    "Identify": [],
    "Protect": [],
    "Detect": [],
    "Respond": [],
    "Recover": []
}

def map_trivy_to_csf(trivy_data):
    for vuln in trivy_data.get("Results", []):
        for item in vuln.get("Vulnerabilities", []):
            severity = item.get("Severity", "")
            if severity in ["CRITICAL", "HIGH"]:
                CSF_CATEGORIES["Identify"].append({
                    "scanner": "Trivy",
                    "name": item.get("VulnerabilityID"),
                    "severity": severity,
                    "package": item.get("PkgName")
                })
            else:
                CSF_CATEGORIES["Protect"].append({
                    "scanner": "Trivy",
                    "name": item.get("VulnerabilityID"),
                    "severity": severity,
                    "package": item.get("PkgName")
                })

def map_bandit_to_csf(bandit_data):
    for issue in bandit_data.get("results", []):
        severity = issue.get("issue_severity", "")
        CSF_CATEGORIES["Protect"].append({
            "scanner": "Bandit",
            "name": issue.get("issue_text"),
            "severity": severity,
            "file": issue.get("filename"),
            "line": issue.get("line_number")
        })

def map_scout_to_csf(scout_data):
    for item in scout_data.get("vulnerabilities", []):
        CSF_CATEGORIES["Protect"].append({
            "scanner": "Docker Scout",
            "name": item.get("title"),
            "severity": item.get("severity"),
            "package": item.get("packageName")
        })

def map_mitre_to_csf(mitre_data):
    for technique in mitre_data.get("techniques", []):
        CSF_CATEGORIES["Detect"].append({
            "scanner": "MITRE ATT&CK",
            "name": technique.get("Name"),
            "technique_id": technique.get("TacticID"),
            "description": technique.get("Description", "")
        })

def load_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            try:
                return json.load(f)
            except:
                return {}
    return {}

def main():
    trivy_json = load_json(os.path.join(REPORTS_DIR, "trivy.json"))
    bandit_json = load_json(os.path.join(REPORTS_DIR, "bandit.json"))
    scout_json = load_json(os.path.join(REPORTS_DIR, "docker_scout.json"))
    mitre_json = load_json(os.path.join(REPORTS_DIR, "mitre_T1003.json"))

    map_trivy_to_csf(trivy_json)
    map_bandit_to_csf(bandit_json)
    map_scout_to_csf(scout_json)
    map_mitre_to_csf(mitre_json)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(CSF_CATEGORIES, f, indent=4)

    print(f"NIST CSF consolidated report saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
