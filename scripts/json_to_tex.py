import json
import re

def latex_escape(text: str, max_len: int = 200) -> str:
    """Escape LaTeX special chars safely and truncate if too long."""
    if not text:
        return "N/A"

    # Normalize whitespace
    text = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")

    # Escape backslashes first
    text = re.sub(r'\\', r'\\textbackslash{}', text)

    # Escape LaTeX special characters
    replacements = {
        "&": r"\&",
        "%": r"\%",
        "_": r"\_",
        "#": r"\#",
        "{": r"\{",
        "}": r"\}",
        "$": r"\$",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    for key, val in replacements.items():
        text = text.replace(key, val)

    # Truncate very long descriptions to avoid TeX buffer overflow
    if len(text) > max_len:
        text = text[:max_len] + "..."

    return text


def main():
    with open("report.json") as f:
        data = json.load(f)

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "UNKNOWN")
            if sev in summary:
                summary[sev] += 1

    with open("report_content.tex", "w") as f:
        f.write("% Auto-generated vulnerability content\n")
        f.write("\\section*{Summary}\n")
        f.write("\\begin{itemize}\n")
        for sev, count in summary.items():
            f.write(f"  \\item {sev}: {count}\n")
        f.write("\\end{itemize}\n\n")

        f.write("\\section*{Vulnerability Details}\n")
        if any(summary.values()):
            f.write(
                "\\begin{longtable}{|p{3cm}|p{2.5cm}|p{2cm}|p{4cm}|p{5cm}|}\n\\hline\n"
            )
            f.write("Package & Vulnerability ID & Severity & Title & Description \\\\\n\\hline\n")

            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    pkg = latex_escape(vuln.get("PkgName") or vuln.get("PkgID") or "N/A")
                    vid = latex_escape(vuln.get("VulnerabilityID", "N/A"))
                    sev = latex_escape(vuln.get("Severity", "N/A"))
                    title = latex_escape(vuln.get("Title", "No title available"))
                    desc = latex_escape(vuln.get("Description", "No description available"), max_len=400)

                    f.write(f"{pkg} & {vid} & {sev} & {title} & {desc} \\\\\n\\hline\n")

            f.write("\\end{longtable}\n")
        else:
            f.write("No vulnerabilities were found in this scan. ✅\n")


if __name__ == "__main__":
    main()
