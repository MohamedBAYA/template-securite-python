import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report

if __name__ == "__main__":
    logger.info("Starting TP1")

    # 1️⃣ Capture et analyse
    capture = Capture()
    capture.capture_trafic()
    capture.analyse("tcp")
    summary = capture.get_summary()

    # 2️⃣ Création du rapport
    filename = "Groupe7.pdf"
    report = Report(capture, filename, summary)

    # ⚠️ Important : générer le tableau avant le save
    report.generate("array")
    report.generate("graph")
    report.save(filename)

    # 3️⃣ Affichage console
    print("\n===== Résumé IDS/IPS =====")
    print(summary)
    print("==========================\n")
