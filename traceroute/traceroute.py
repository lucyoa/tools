#!/usr/bin/env python

import sys
import signal
import argparse
import dns.resolver, dns.reversename
from scapy.all import *

conf.verb = 0


def signal_handler(signal, frame):
    sys.exit(0)


def resolve_ip(ip):
    hostname = ip
    my_resolver = dns.resolver.Resolver()

    try:
        reversename = dns.reversename.from_address(ip)
        hostname = str(my_resolver.query(reversename, "PTR")[0])[:-1]
    except Exception:
        pass

    return hostname


def main():
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser()
    parser.add_argument("--udp", action="store_true", help="use UDP technique")
    parser.add_argument("--icmp", action="store_true", help="use ICMP technique") 
    parser.add_argument("-t", "--timeout", type=int, default=2, help="timeout for packets")

    parser.add_argument("target")

    args = parser.parse_args(sys.argv[1:])

    if not args.target: 
        return

    print("Traceroute to {}:".format(args.target), end="")
    for i in range(1, 32):
        print("\n{:2}: ".format(i), end="")
        for _ in range(3):  # 3 retries
            if args.icmp:
                res = sr1(IP(dst=args.target, ttl=i) / ICMP(), timeout=args.timeout)
            else:
                res = sr1(IP(dst=args.target, ttl=i) / UDP(dport=33434), timeout=args.timeout)

            if res:
                print("{} ({})".format(resolve_ip(res.src), res.src), end="")
                if res.type in [0, 3]:
                    print()
                    sys.exit(0)
                break
            else:
                print("* ", end="", flush=True)


if __name__ == "__main__":
    main()
