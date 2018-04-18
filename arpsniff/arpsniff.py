#!/usr/bin/env python

import sniffer


def main():
    arpmonitor = sniffer.ARPSniffer()
    arpmonitor.sniff()

if __name__ == "__main__":
    main()
