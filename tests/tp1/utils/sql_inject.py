import socket
import time

target_ip = "google.com"
target_port = 80

# simule un payload d'injection SQL
payloads = [
    "SELECT * FROM users WHERE id = 1;",
    "UNION SELECT password FROM admins;",
    "GET /search.php?q=UNION+SELECT+1,2,3-- HTTP/1.1\r\nHost: example.com\r\n\r\n",
]

print("[*] Envoi de requêtes SQL simulées vers ->", target_ip)

for payload in payloads:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, target_port))
        s.send(payload.encode())
        s.close()
        print(f"  > Envoyé : {payload}")
        time.sleep(1)
    except Exception as e:
        print(f"Erreur : {e}")

print("[*] Terminé.")
