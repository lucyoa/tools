#!/usr/bin/env python

import sys
import argparse
import monitor


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--range", help="ipv4 range of assets")

    args = parser.parse_args(sys.argv[1:])

    if not args.range:
        return 

    ip_range = args.range

    mon = monitor.Monitor(ip_range) 
    mon.run()

if __name__ == "__main__":
    main()
