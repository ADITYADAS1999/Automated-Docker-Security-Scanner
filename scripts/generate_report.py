import os
import json
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle,
    Paragraph, Spacer, Image
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import matplotlib.pyplot as plt

try:
    from PyPDF2 import PdfMerger
    USE_PYPDF2 = True
except ImportError:
    from pypdf import PdfWriter
    USE_PYPDF2 = False


def load_json(file_path):
    """Load JSON safely from a file."""
    try:
        with open(file_path) as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Could not load {file_path}: {e}")
        return {}


def generate_charts(summary):
    """Generate bar and pie charts for severity summary."""
    severities = list(summary.keys())
    counts = list(summary.values())

    plt.figure(figsize=(5, 3))
    plt.bar(severities, counts, color=["red", "orange", "gold", "green"])
    plt.title("Vulnerabilities by Severity")
    plt.xlabel("Severity")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig("bar_chart.png")
    plt.close()

    plt.figure(figsize=(4, 4))
    plt.pie(counts, labels=severities, autopct="%1.1f%%",
            colors=["red", "orange", "gold", "green"], startangle=140)
    plt.title("Severity Distribution")
    plt.tight_layout()
    plt.savefig("pie_chart.png")
    plt.close()


def merge_pdfs(front_page, report, output):
    if USE_PYPDF2:
        merger = PdfMerger()
        merger.append(front_page)
        merger.append(report)
        merger.write(output)
        merger.close()
    else:
        writer = PdfWriter()
        writer.append(front_page)
        writer.append(report)
        with open(output, "wb") as f:
            writer.write(f)


def generate_report():
    reports_dir = "reports"
    files = {
        "Trivy": os.path.join(reports_dir, "trivy.json"),
        "Docker Scout": os.path.join(reports_dir, "docker_scout.json"),
        "Bandit": os.path.join(reports_dir, "bandit.json"),
        "MITRE ATT&CK": os.path.join(reports_dir, "mitre_T1003.json"),
        "OWASP ZAP": os.path.join(reports_dir, "zap.json"),  # optional
    }

    # PDF build
    doc = SimpleDocTemplate("report_content.pdf", pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()

    # Title
    elements.append(Paragraph("<b>Unified Security Report</b>", styles["Title"]))
    elements.append(Spacer(1, 20))

    # Global severity summary
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    # Process each tool's results
    for tool, path in files.items():
        data = load_json(path)
        if not data:
            continue

        elements.append(Paragraph(f"<b>{tool} Findings:</b>", styles["Heading2"]))

        table_data = [["ID/Package", "Severity", "Description/Title"]]

        if tool == "Trivy":
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    sev = vuln.get("Severity", "UNKNOWN")
                    if sev in summary:
                        summary[sev] += 1
                    table_data.append([
                        vuln.get("VulnerabilityID", "N/A"),
                        sev,
                        vuln.get("Title", "N/A")
                    ])

        elif tool == "Bandit":
            for issue in data.get("results", []):
                sev = issue.get("issue_severity", "UNKNOWN").upper()
                if sev in summary:
                    summary[sev] += 1
                table_data.append([
                    issue.get("test_id", "N/A"),
                    sev,
                    issue.get("issue_text", "N/A")
                ])

        elif tool == "OWASP ZAP":
            for site in data.get("site", []):
                for alert in site.get("alerts", []):
                    sev = alert.get("riskdesc", "UNKNOWN").split()[0].upper()
                    if sev in summary:
                        summary[sev] += 1
                    table_data.append([
                        alert.get("alert", "N/A"),
                        sev,
                        alert.get("desc", "N/A")[:80]
                    ])

        else:
            table_data.append(["N/A", "N/A", "Report parsing not yet implemented"])

        table = Table(table_data, colWidths=[120, 60, 280])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#cccccc")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))

    # Add charts
    generate_charts(summary)
    elements.append(Image("bar_chart.png", width=350, height=200))
    elements.append(Spacer(1, 20))
    elements.append(Image("pie_chart.png", width=300, height=300))

    # Build
    doc.build(elements)

    merge_pdfs("report_format.pdf", "report_content.pdf", "report.pdf")


if __name__ == "__main__":
    generate_report()
