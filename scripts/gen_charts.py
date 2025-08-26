import json
import matplotlib.pyplot as plt
from pathlib import Path

data = {}
if Path("report.json").exists() and Path("report.json").stat().st_size > 0:
    try:
        with open("report.json") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        data = {}

summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        sev = vuln.get("Severity", "UNKNOWN")
        if sev in summary:
            summary[sev] += 1

plt.figure(figsize=(5,5))
if sum(summary.values()) > 0:
    labels = list(summary.keys())
    sizes = list(summary.values())
    colors = ['#d73027','#fc8d59','#fee08b','#91cf60']
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.title("Vulnerability Severity Distribution")
else:
    plt.text(0.5, 0.5, "No Vulnerabilities Found ✅", ha="center", va="center", fontsize=14)
    plt.axis("off")

plt.savefig("assets/severity_chart.png")
