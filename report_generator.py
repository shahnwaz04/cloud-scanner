from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import TableStyle
import os

def generate_pdf(report_data):

    os.makedirs("reports", exist_ok=True)

    pdf_path = "reports/security_report.pdf"
    doc = SimpleDocTemplate(pdf_path)

    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("AWS Security Scan Report", styles["Title"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph(f"Account ID: {report_data['account_id']}", styles["Normal"]))
    elements.append(Paragraph(f"Risk Score: {report_data['risk_score']}/100", styles["Normal"]))
    elements.append(Spacer(1, 12))

    table_data = [["Service", "Resource", "Issue", "Severity"]]

    for f in report_data["findings"]:
        table_data.append([
            f["service"],
            f["resource"],
            f["issue"],
            f["severity"]
        ])

    table = Table(table_data)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
    ]))

    elements.append(table)
    doc.build(elements)