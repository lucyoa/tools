#!/usr/bin/env python3

import sys
import argparse
from upnp.upnp import UPNP


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--discover", action="store_true", help="Discover UPNP devices")
    parser.add_argument("--enum", action="store_true", help="Enumerate UPNP device")
    parser.add_argument("--fuzz", action="store_true", help="Fuzz action")
    parser.add_argument("--target", required=False)
    parser.add_argument("--control", required=False)
    parser.add_argument("--service", required=False)
    parser.add_argument("--action", required=False)

    args = parser.parse_args(sys.argv[1:])
    upnp = UPNP()

    if args.discover:
        upnp.discover()
    elif args.enum:
        upnp.enum(args.target)
    elif args.fuzz:
        upnp.fuzz(args.target, args.control, args.service, args.action)


if __name__ == "__main__":
    main()
