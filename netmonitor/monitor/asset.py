import time
from monitor.utils import (
    vendor_lookup,
    resolve_ip,
    lookup_dhcpv4,
    EVENTS,
)


class Asset(object):
    def __init__(self, mac, ip=None):
        self.mac = mac
        self.ip = ip
        self.vendor = vendor_lookup(mac)
        self.hostname = resolve_ip(ip) if ip else None
        self.dhcpv4 = None

        self.info = None

        self.active = None
        self.last_seen = int(time.time())
        self.events = []

    def print_info(self):
        status = "\033[92m[+]\033[0m" if self.active else "\033[91m[-]\033[0m"
        print("{} {} ({}) - {}".format(status, self.ip, self.mac, self.vendor))
        print("Hostname: {}".format(self.hostname))

        if self.info:
            print("Info: {}".format(self.info))

        print("Last seen: {}".format(time.strftime("%H:%M:%S %d.%m.%Y", time.gmtime(self.last_seen))))
        for event in self.events:
            print(" - {} - {}".format(event["event"], event["time"]))
        print()


    def dhcp_request(self, hostname, dhcpv4):
        self.last_seen = int(time.time())

        self.hostname = hostname
        self.dhcpv4 = dhcpv4

        if not self.info:
           self.info = lookup_dhcpv4(self.dhcpv4)

        self._add_event("dhcp request")

    def appeared(self, ip):
        self.last_seen = int(time.time())

        self.ip = ip 

        if not self.active:
            self.active = True
            self._add_event("appeared")

    def disappeared(self):
        if self.active: 
            self.active = False
            self._add_event("disappeared")

    def _add_event(self, event):
        self.events.append(
            {"event": event, "time": time.strftime("%H:%M:%S %d.%m.%Y", time.gmtime(time.time()))}
        )

        for ev in EVENTS:
            if ev.trigger(event, self):
                ev.execute()
