from scapy.all import sniff
from sniffer.dhcp_pkt import DHCPPkt

class DHCPSniffer(object):
    def sniff(self):
        sniff(filter="udp and (port 67 or 68)",
              prn=self.parse_dhcp)

    def parse_dhcp(self, pkt):
        dhcp_pkt = DHCPPkt(pkt)
        dhcp_pkt.print_info()
