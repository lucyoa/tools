#!/usr/bin/env python

import sys
import time
import threading
import argparse
import utils 

from scapy.all import (
    sniff,
    srp,
    Ether,
    ARP,
    conf,
)


class Asset(object):
    def __init__(self, mac, ip):
        self.mac = mac
        self.ip = ip
        self.vendor = utils.vendor_lookup(mac)
        self.name = utils.resolve_ip(ip)

        self.active = None
        self.last_seen = None
        self.events = []

        self.appeared()

    def print_info(self):
        status = "\033[92m[+]\033[0m" if self.active else "\033[91m[-]\033[0m"
        print("{} {} ({}) - {}".format(status, self.ip, self.mac, self.vendor))
        print("Hostname: {}".format(self.name))
        print("Last seen: {}".format(time.strftime("%H:%M:%S %d.%m.%Y", time.gmtime(self.last_seen))))
        for event in self.events:
            print(" - {} - {}".format(event["event"], event["time"]))
        print()

    def appeared(self):
        self.last_seen = int(time.time())

        if not self.active:
            self.active = True
            self._add_event("appeared")
            return True

        return False

    def disappeared(self):
        if self.active: 
            self.active = False
            self._add_event("disappeared")
            return True

        return False

    def _add_event(self, event):
        self.events.append(
            {"event": event, "time": time.strftime("%H:%M:%S %d.%m.%Y", time.gmtime(time.time()))}
        )



class SniffThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

        self.e = threading.Event()
        self.assets = []

        self.last_display = None 
        self.display_delay = 2

    def run(self):
        sniff(filter="arp",
              prn=self.parse_packet,
              stop_filter=lambda p: self.e.is_set())

    def parse_packet(self, pkt):
        if pkt[Ether].src in ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"] or \
           pkt[ARP].psrc in ["127.0.0.1", "0.0.0.0"]:
            return

        asset = self.get_asset(pkt[Ether].src)
        if not asset:
            asset = Asset(pkt[Ether].src, pkt[ARP].psrc)
            self.assets.append(asset)
        else:
            asset.appeared()

        now = int(time.time())
        for asset in self.assets:
            if now - asset.last_seen > 120:
                asset.disappeared()

        if not self.last_display or now - self.last_display > self.display_delay:
            self.last_display = now
            self.display_assets()

    def get_asset(self, mac):
        for asset in self.assets:
            if asset.mac == mac:
               return asset 
        return None

    def display_assets(self):
        print("\033[H\033[J")
        print("Monitoring assets...\n") 
        for asset in self.assets:
            asset.print_info()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--range", help="ipv4 range of assets")
    parser.add_argument("--passive", help="don't send any packets", action="store_true")

    args = parser.parse_args(sys.argv[1:])

    if not args.range:
        return 

    ip_range = args.range
    passive = False if not args.passive else True 

    sniff = SniffThread()
    sniff.start()

    try:
        if not passive:
            conf.verb = 0
    
            while True:
                srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=5)
                time.sleep(60)
    
        sniff.join()
    except KeyboardInterrupt:
        sniff.e.set()


if __name__ == "__main__":
    main()
