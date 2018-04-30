from arpdiscover.sniffer import Sniffer
from scapy.all import (
    conf,
    srp,
    Ether,
    ARP
)


class ArpDiscover(object):
    def __init__(self, ip_range, passive=False):
        self.ip_range = ip_range
        self.sniffer = Sniffer()

    def run(self):
        self.sniffer.start()
        self.ping_arp()
        self.sniffer.join()

    def ping_arp(self):
        print("Scanning range: {}".format(self.ip_range))
        conf.verb = 0
        srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.ip_range), timeout=5)
