from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from datetime import datetime
import tempfile
import os


class Report:
    def __init__(self, capture, filename, summary):
        self.capture = capture
        self.filename = filename
        self.title = "RAPPORT D'ANALYSE IDS"
        self.summary = summary if summary else "Résumé indisponible"
        self.array = ""
        self.graph_svg = ""

    def generate(self, param: str) -> None:
        if param == "graph":
            import pygal

            data = self.capture.get_all_protocols()
            bar_chart = pygal.Bar(width=600, height=400, explicit_size=True)
            bar_chart.title = "Trafic réseau par protocole"
            for proto, count in data.items():
                bar_chart.add(proto, count)
            self.graph_svg = bar_chart.render()

        elif param == "array":
            sorted_data = self.capture.sort_network_protocols()
            table = f"{'Protocole':<10} | {'Nombre de paquets':<18}\n"
            table += "-" * 32 + "\n"
            for proto, count in sorted_data:
                table += f"{proto:<10} | {count:<18}\n"
            self.array = table

    def save(self, filename: str) -> None:
        c = canvas.Canvas(filename, pagesize=A4)
        width, height = A4
        y = height - 2 * cm

        def draw_line(text, spacing=14, bold=False):
            nonlocal y
            if y < 3 * cm:
                c.showPage()
                y = height - 2 * cm
            c.setFont("Helvetica-Bold" if bold else "Helvetica", 10)
            c.drawString(2 * cm, y, text)
            y -= spacing

        def draw_multiline_block(block_text, spacing=14):
            for line in block_text.strip().split("\n"):
                draw_line(line, spacing=spacing)

        # Titre
        draw_line(self.title, spacing=20, bold=True)

        # Infos générales
        draw_line(f"Date : {datetime.now().strftime('%d/%m/%Y à %Hh%M')}")
        draw_line(f"Interface : {self.capture.interface}")
        draw_line(f"Paquets capturés : {len(self.capture.packets)}")
        draw_line(" ")

        # Résumé IDS
        draw_line("1. Analyse du trafic réseau - Résumé IDS", spacing=16, bold=True)
        draw_line("Résultats :")
        draw_multiline_block(self.summary)

        # Tableau des protocoles
        draw_line(" ")
        draw_line("2. Statistiques des protocoles", spacing=16, bold=True)
        draw_multiline_block(self.array)

        # Graphique
        if self.graph_svg:
            draw_line(" ")
            draw_line("3. Graphique des protocoles", spacing=16, bold=True)

            from cairosvg import svg2png

            temp_svg = tempfile.NamedTemporaryFile(delete=False, suffix=".svg")
            temp_png = tempfile.NamedTemporaryFile(delete=False, suffix=".png")

            temp_svg.write(self.graph_svg)
            temp_svg.close()
            svg2png(url=temp_svg.name, write_to=temp_png.name)

            image_width = 15 * cm
            image_height = 10 * cm
            x_center = (width - image_width) / 2

            if y < image_height + 3 * cm:
                c.showPage()
                y = height - 2 * cm

            y -= 10
            c.drawImage(
                temp_png.name, x_center, y - image_height, width=image_width, height=image_height, mask="auto"
            )
            y -= image_height + 20

            os.unlink(temp_svg.name)
            os.unlink(temp_png.name)

        c.save()
        print(f"[✔] Rapport PDF sauvegardé dans : {filename}")
