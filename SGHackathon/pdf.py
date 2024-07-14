from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, "PDF Report", 0, 1, "C")
    
    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", 0, 0, "C")
    
    def chapter_title(self, title):
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, title, 0, 1, "L")
        self.ln(5)
    
    def chapter_body(self, body):
        self.set_font("Arial", "", 12)
        self.multi_cell(0, 10, body)
        self.ln()
    
    def add_image(self, image_path):
        self.image(image_path, x=10, w=180)
        self.ln(10)
    
    def security_section(self, filename):
        self.set_font("Arial", "B", 12)
        self.ln(5)
        self.set_font("Arial", "", 12)
        with open(filename, 'r') as file:
            content = file.read()
            self.multi_cell(0, 10, content)
        self.ln(10)
