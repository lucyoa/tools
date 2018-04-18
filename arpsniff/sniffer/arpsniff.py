from scapy.all import sniff
from sniffer.arp_pkt import ArpPkt


class ArpSniff(object):
    def sniff(self):
        sniff(filter="arp",
              prn=self.parse_arp)

    def parse_arp(self, pkt):
        arp = ArpPkt(pkt)
        arp.print_info()
