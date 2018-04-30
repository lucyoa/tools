#!/usr/bin/env python

import sys
import argparse
import arpdiscover


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--range", help="ipv4 range of ip addresses")

    args = parser.parse_args(sys.argv[1:])

    if not args.range:
        return

    ip_range = args.range

    arp_discover = arpdiscover.ArpDiscover(ip_range)
    arp_discover.run()


if __name__ == "__main__":
    main()
