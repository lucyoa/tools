#!/usr/bin/env python

import sniffer

def main():
    dhcp_sniffer = sniffer.DHCPSniffer()
    dhcp_sniffer.sniff()
    

if __name__ == "__main__":
    main()
