from src.tp1.utils.lib import choose_interface
from src.tp1.utils.config import logger
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP
from collections import defaultdict


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.packets = []
        self.summary = ""

    def capture_trafic(self) -> None:
        """
        Capture network trafic from the selected interface
        """
        logger.info(f"Démarrage de la capture sur l'interface {self.interface}")
        try:
            self.packets = sniff(iface=self.interface, timeout=30)
            logger.info(f"Capture terminée : {len(self.packets)} paquets capturés.")
        except Exception as e:
            logger.error(f"Erreur lors de la capture : {e}")

    def sort_network_protocols(self) -> list:
        """
        Sort and return all captured network protocols (by packet count, descending)
        """
        protocol_counts = self.get_all_protocols()
        sorted_protocols = sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True)
        logger.info(f"Protocoles triés : {sorted_protocols}")
        return sorted_protocols

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        """
        protocol_counts = defaultdict(int)

        for pkt in self.packets:
            if pkt.haslayer(ARP):
                protocol_counts["ARP"] += 1
            elif pkt.haslayer(ICMP):
                protocol_counts["ICMP"] += 1
            elif pkt.haslayer(TCP):
                protocol_counts["TCP"] += 1
            elif pkt.haslayer(UDP):
                protocol_counts["UDP"] += 1
            elif pkt.haslayer(IP):
                protocol_counts["IP"] += 1
            else:
                protocol_counts["Autre"] += 1

        logger.info(f"Protocoles détectés : {dict(protocol_counts)}")
        return dict(protocol_counts)

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        """
        summary_lines = []
        alerts = []

        # 🔍 Détection ARP Spoofing
        arp_replies = defaultdict(set)

        for pkt in self.packets:
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                arp_replies[ip].add(mac)

        for ip, macs in arp_replies.items():
            if len(macs) > 1:  # Même IP avec plusieurs MACs
                mac_list = ", ".join(macs)
                alerts.append(f"[ALERTE] ARP Spoofing détecté pour {ip} : {mac_list}")

        # 🔍 Détection SQLi (hors de la boucle ARP !)
        for pkt in self.packets:
            if pkt.haslayer(TCP) and hasattr(pkt.payload, "load"):
                try:
                    raw = pkt.payload.load.decode(errors="ignore")
                    if "SELECT" in raw.upper() or "UNION" in raw.upper():
                        ip_attacker = pkt[IP].src if pkt.haslayer(IP) else "IP inconnue"
                        alerts.append(f"[ALERTE] Tentative d'injection SQL depuis {ip_attacker}")
                except Exception:
                    pass

        if alerts:
            summary_lines.append("/!\ Trafic illégitime détecté :\n")
            summary_lines.extend(alerts)
        else:
            summary_lines.append("[✔] Aucun comportement suspect détecté.")

        self.summary = "\n".join(summary_lines)

    def gen_summary(self) -> str:
        """
        Generate summary
        """
        return self.summary
