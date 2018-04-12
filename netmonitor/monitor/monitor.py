import time
import threading
import subprocess
from monitor.asset import Asset
from scapy.all import (
    sniff,
    srp,
    Ether,
    ARP,
    conf
)


ASSETS = []


class Sniffer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

        self.e = threading.Event()
        self.last_display = None 

    def run(self):
        sniff(filter="arp",
              prn=self.parse_packet,
              stop_filter=lambda p: self.e.is_set())

    def parse_packet(self, pkt):
        if not pkt.haslayer(ARP) or \
           pkt[Ether].src in ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"] or \
           pkt[ARP].psrc in ["127.0.0.1", "0.0.0.0"]:
            return

        asset = self.get_asset(pkt[Ether].src)
        if not asset:
            asset = Asset(pkt[Ether].src, pkt[ARP].psrc)
            ASSETS.append(asset)
        else:
            asset.appeared()

        now = int(time.time())
        for asset in ASSETS:
            if now - asset.last_seen > 120:
                asset.disappeared()

    def get_asset(self, mac):
        for asset in ASSETS:
            if asset.mac == mac:
               return asset 
        return None


class Job(object):
    def __init__(self, fn, interval , args=None):
        self.fn = fn
        self.interval = interval 
        self.args = args 
        self.last_triggered = None


class Monitor(object):
    def __init__(self, ip_range):
        self.jobs = []
        self.ip_range = ip_range

        self.sniffer = Sniffer()
        self.sniffer.start()

        self.last_displayed = None

    def schedule(self, fn, interval, args=None):
        job = Job(fn, interval, args)
        self.jobs.append(job)

    def run(self):
        try:
            self.schedule(self.ping_arp, 60, args=[self.ip_range])
            self.monitor()
        except KeyboardInterrupt:
            self.clear()

    def monitor(self):
        while True:
            now = int(time.time())

            for job in self.jobs:
                if not job.last_triggered or now - job.last_triggered > job.interval:
                    job.last_triggered = now

                    if job.args:
                        thread = threading.Thread(target=job.fn, args=job.args)
                    else:
                        thread = threading.Thread(target=job.fn)

                    thread.start()

            if not self.last_displayed or now - self.last_displayed > 1:
                self.last_displayed = now
                self.display_interface()

    def clear(self):
        self.sniffer.e.set()

    def display_interface(self):
        print("\033[H\033[J")
        print("""         ,\\
         \\\\\\,_
          \\` ,\\
     __,.-" =__)
   ."        )
,_/   ,    \\/\\_  NetMonitor
\_|    )_-\\ \\_-`    v0.1
  `-----` `--`""")

        print("Monitoring assets...\n") 
        for asset in ASSETS:
            asset.print_info()

    def ping_arp(self, ip_range):
        conf.verb = 0
        srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=5)
