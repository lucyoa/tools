#!/usr/bin/env python

import sys
import argparse
from scanner.scanner import Scanner
import scanner.utils as utils


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-sT", "--tcp", action="store_true", help="TCP Connect scan")
    parser.add_argument("-sS", "--syn", action="store_true", help="TCP Syn scan")
    parser.add_argument("-sN", "--null", action="store_true", help="TCP Null scan")
    parser.add_argument("-sF", "--fin", action="store_true", help="TCP Fin scan")
    parser.add_argument("-sX", "--xmas", action="store_true", help="TCP XMas scan")
    parser.add_argument("-sA", "--ack", action="store_true", help="TCP Ack scan")
    parser.add_argument("-sU", "--udp", action="store_true", help="UDP scan")
    parser.add_argument("-p", "--ports", nargs="*")
    parser.add_argument("target")

    args = parser.parse_args(sys.argv[1:])
    
    if args.ports and args.ports != "top":
        ports = utils.parse_ports(args.ports) 
    else:
        ports = utils.get_top_ports(1000)

    scanner = Scanner(args.target, ports)
    if args.tcp:
        scanner.scan(technique="tcp")
    elif args.syn:
        scanner.scan(technique="syn")
    elif args.null:
        scanner.scan(technique="null")
    elif args.fin:
        scanner.scan(technique="fin")
    elif args.xmas:
        scanner.scan(technique="xmas")
    elif args.ack:
        scanner.scan(technique="ack")

    if args.udp:
        scanner.scan(technique="udp")

if __name__ == "__main__":
    main()
