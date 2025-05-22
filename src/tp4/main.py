# http://31.220.95.27:13337/

#  GG ! Flag : ESGI{G00d_Pr0gr4mmer}

from pwn import *
import base64
import binascii

# Table Morse inversée
MORSE_DICT = {
    '.-': 'A',    '-...': 'B',  '-.-.': 'C',  '-..': 'D',
    '.': 'E',     '..-.': 'F',  '--.': 'G',   '....': 'H',
    '..': 'I',    '.---': 'J',  '-.-': 'K',   '.-..': 'L',
    '--': 'M',    '-.': 'N',    '---': 'O',   '.--.': 'P',
    '--.-': 'Q',  '.-.': 'R',   '...': 'S',   '-': 'T',
    '..-': 'U',   '...-': 'V',  '.--': 'W',   '-..-': 'X',
    '-.--': 'Y',  '--..': 'Z',
    '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9'
}

def decode_morse(morse_str):
    return ''.join(MORSE_DICT.get(code, '?') for code in morse_str.strip().split())

def smart_decode(encoded):
    encoded = encoded.strip()

    # Try base64
    try:
        b64 = base64.b64decode(encoded, validate=True).decode()
        return b64
    except Exception:
        pass

    # Try hex
    try:
        hexd = bytes.fromhex(encoded).decode()
        return hexd
    except Exception:
        pass

    # Try Morse
    if all(c in ".- " for c in encoded):
        morse_decoded = decode_morse(encoded)
        return morse_decoded.lower()  # Le serveur semble attendre lowercase
    return None

def main():
    host = "31.220.95.27"
    port = 13337

    while True:
        try:
            conn = remote(host, port, timeout=3)
            while True:
                line = conn.recvline(timeout=1).decode(errors="ignore").strip()
                print("[RECV]", line)

                if "A décoder:" in line:
                    encoded = line.split("A décoder: ")[1]
                    decoded = smart_decode(encoded)
                    if decoded:
                        print("[SEND]", decoded)
                        conn.sendline(decoded.encode())
                    else:
                        print("[!] Décodage impossible :", encoded)
                        break

                if "Flag" in line or "ESGI" in line:
                    print("[✅ ] Flag trouvé :", line)
                    return
        except Exception as e:
            print("[!] Erreur :", e)

if __name__ == "__main__":
    main()
