import threading
from arpdiscover.asset import Asset
from scapy.all import (
    sniff,
    Ether,
    ARP
)


class Sniffer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.e = threading.Event()

        self.assets = []

    def run(self):
        sniff(filter="arp",
              prn=self.parse_arp,
              stop_filter=lambda p: self.e.is_set(),
              store=0)

    def parse_arp(self, pkt):
        if not pkt.haslayer(ARP):
            return

        mac = pkt[Ether].src
        ip = pkt[ARP].psrc

        if mac in ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"] or \
           ip in ["127.0.0.1", "0.0.0.0"]:
            return

        asset = self.get_asset(mac)
        if not asset:
            asset = Asset(mac, ip)
            asset.print_info()
            self.assets.append(asset)

    def get_asset(self, mac):
        for asset in self.assets:
            if asset.mac == mac:
                return asset
        return None
