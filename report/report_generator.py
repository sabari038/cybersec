from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def generate_pdf_report(data, filename='vulnerability_report.pdf'):
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    y = height - 40

    c.setFont('Helvetica', 14)
    c.drawString(30, y, "Windows Vulnerability Scan Report")
    y -= 30

    for section, details in data.items():
        c.setFont('Helvetica-Bold', 12)
        c.drawString(30, y, section)
        y -= 20

        c.setFont('Helvetica', 10)
        if isinstance(details, dict) or isinstance(details, list):
            for line in str(details).split('\n'):
                c.drawString(40, y, line)
                y -= 15
                if y < 50:
                    c.showPage()
                    y = height - 40
        else:
            c.drawString(40, y, str(details))
            y -= 20

    c.save()

if __name__ == "__main__":
    sample_data = {'Example': {'Key': 'Value'}}
    generate_pdf_report(sample_data)
