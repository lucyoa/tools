#!/usr/bin/env python

import sys
from arpspoof.spoof import Spoof

def main():
    if len(sys.argv) != 3:
        print("Usage: {} <target1_ip> <target2_ip>".format(sys.argv[0]))
        sys.exit(0)

    spoofer = Spoof(sys.argv[1], sys.argv[2])
    spoofer.spoof()

if __name__ == "__main__":
    main()
