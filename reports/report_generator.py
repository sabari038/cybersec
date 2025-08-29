from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import os
from textwrap import wrap

class ReportGenerator:
    def __init__(self, filename="vulnerability_report.pdf"):
        self.filename = filename
        self.styles = getSampleStyleSheet()
        self.story = []

    def add_section(self, title, content):
        """
        Add a neatly formatted section to the PDF.
        - dict => table
        - list => bullet points
        - str  => paragraph
        """
        # Section header
        self.story.append(Paragraph(f"<b><font size=14>{title}</font></b>", self.styles["Heading2"]))
        self.story.append(Spacer(1, 10))

        if isinstance(content, dict):
            # Table for dictionary data
            data = [["Item", "Details"]]
            for k, v in content.items():
                if isinstance(v, (list, dict)):
                    v = str(v)
                v = "\n".join(wrap(str(v), 80))
                data.append([str(k), v])

            table = Table(data, colWidths=[150, 350])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#003366")),
                ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
                ("ALIGN", (0,0), (-1,-1), "LEFT"),
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE", (0,0), (-1,-1), 9),
                ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
                ("VALIGN", (0,0), (-1,-1), "TOP"),
            ]))
            self.story.append(table)

        elif isinstance(content, list):
            # Bullet points for lists
            for item in content:
                self.story.append(Paragraph(f"• {str(item)}", self.styles["Normal"]))

        else:
            # Paragraph for plain strings
            self.story.append(Paragraph(str(content), self.styles["Normal"]))

        self.story.append(Spacer(1, 20))

    def add_image(self, image_path, caption="Network Map"):
        """
        Add an image (network graph) to the PDF.
        """
        if os.path.exists(image_path):
            self.story.append(PageBreak())
            img = Image(image_path, width=450, height=300)
            self.story.append(img)
            self.story.append(Spacer(1, 10))
            self.story.append(Paragraph(f"<i>{caption}</i>", self.styles["Italic"]))
            self.story.append(Spacer(1, 20))

    def build(self):
        doc = SimpleDocTemplate(self.filename, pagesize=letter)
        doc.build(self.story)
        print(f"[+] Clean PDF report generated: {self.filename}")
