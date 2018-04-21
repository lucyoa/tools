#!/usr/bin/env python

from scapy.all import *


def main():
    localmac = get_if_hwaddr(conf.iface)
    hw = bytes([int(x, 16) for x in localmac.split(":")])

    dhcp_discover = Ether(src=localmac, dst="ff:ff:ff:ff:ff:ff", type=0x800)\
                   /IP(src="0.0.0.0",dst="255.255.255.255")\
                   /UDP(sport=68,dport=67)/BOOTP(chaddr=hw)\
                   /DHCP(options=[("message-type", "discover")])

    conf.verb = 0
    conf.checkIPaddr = False

    ans, unans = srp(dhcp_discover, timeout=10)

    for snd, rcv in ans:
        print("== Response from DHCP server: {} ({}) ==".format(rcv[IP].src, rcv[Ether].src))
        for option in rcv[DHCP].options:
            if option == "end":
                break

            print("{}: {}".format(option[0], option[1]))
        print()

if __name__ == "__main__":
    main()
