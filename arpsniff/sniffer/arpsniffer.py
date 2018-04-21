from scapy.all import sniff
from sniffer.arp_pkt import ARPPkt 


class ARPSniffer(object):
    def sniff(self):
        sniff(filter="arp",
              prn=self.parse_arp,
              store=0)

    def parse_arp(self, pkt):
        arp = ARPPkt(pkt)
        arp.print_info()
