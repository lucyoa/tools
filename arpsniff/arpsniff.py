#!/usr/bin/env python

import sniffer


def main():
    arpmonitor = sniffer.ArpSniff()
    arpmonitor.sniff()

if __name__ == "__main__":
    main()
