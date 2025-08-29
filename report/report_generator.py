from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf_report(data, filename='vulnerability_report.pdf'):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    # Title
    elements.append(Paragraph("<b>Windows Vulnerability Scan Report</b>", styles["Title"]))
    elements.append(Spacer(1, 12))

    # --- System Info ---
    elements.append(Paragraph("<b>System Information</b>", styles["Heading2"]))
    sysinfo = data.get("System Information", {})
    for key, val in sysinfo.get("Basic Info", {}).items():
        elements.append(Paragraph(f"<b>{key}:</b> {val}", styles["Normal"]))
    if ".NET Versions" in sysinfo:
        elements.append(Paragraph(f"<b>.NET Versions:</b> {', '.join(sysinfo['.NET Versions'])}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    # --- Network Info ---
    elements.append(Paragraph("<b>Network Information</b>", styles["Heading2"]))
    netinfo = data.get("Network Information", {})
    if "Open Ports" in netinfo:
        ports_str = ", ".join(str(p) for p in netinfo["Open Ports"])
        elements.append(Paragraph(f"<b>Open Ports:</b> {ports_str}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    # --- CVE Data ---
    elements.append(Paragraph("<b>Potential Vulnerabilities (NVD)</b>", styles["Heading2"]))
    cve_data = data.get("Potential Vulnerabilities (NVD)", {})
    matches = cve_data.get("matches", [])

    if matches:
        table_data = [["CVE ID", "Severity", "CVSS", "Matched", "Description"]]

        for m in matches[:20]:  # Show only top 20 for readability
            sev = m.get("severity", "Unknown")
            color = colors.black
            if sev == "CRITICAL":
                color = colors.red
            elif sev == "HIGH":
                color = colors.orange
            elif sev == "MEDIUM":
                color = colors.blue
            elif sev == "LOW":
                color = colors.green

            row = [
                m.get("cve", ""),
                Paragraph(f'<font color="{color2hex(color)}"><b>{sev}</b></font>', styles["Normal"]),
                str(m.get("cvss", "N/A")),
                m.get("matched_on", ""),
                Paragraph(m.get("description", ""), styles["Normal"])
            ]
            table_data.append(row)

        table = Table(table_data, colWidths=[80, 70, 50, 100, 220])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.black),
            ("BOX", (0, 0), (-1, -1), 0.25, colors.black),
        ]))
        elements.append(table)
    else:
        elements.append(Paragraph("No CVEs found.", styles["Normal"]))

    doc.build(elements)


def color2hex(color):
    """Convert ReportLab color to hex string."""
    return "#%02x%02x%02x" % (
        int(color.red * 255),
        int(color.green * 255),
        int(color.blue * 255)
    )


if __name__ == "__main__":
    sample_data = {
        "System Information": {"Basic Info": {"OS": "Windows 11", "OS Version": "10.0.26100"}, ".NET Versions": ["4.8", "3.5"]},
        "Network Information": {"Open Ports": [80, 443, 3306]},
        "Potential Vulnerabilities (NVD)": {
            "matches": [
                {"cve": "CVE-2024-1234", "severity": "HIGH", "cvss": 7.8, "matched_on": "Windows 11", "description": "Sample vulnerability affecting Windows 11."},
                {"cve": "CVE-2023-5678", "severity": "CRITICAL", "cvss": 9.8, "matched_on": "OpenSSL 1.1.1", "description": "Remote code execution in OpenSSL."}
            ]
        }
    }
    generate_pdf_report(sample_data)
