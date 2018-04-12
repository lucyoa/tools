import time
from monitor.utils import (
    vendor_lookup,
    resolve_ip,
    EVENTS,
)


class Asset(object):
    def __init__(self, mac, ip):
        self.mac = mac
        self.ip = ip
        self.vendor = vendor_lookup(mac)
        self.hostname = resolve_ip(ip)

        self.active = None
        self.last_seen = None
        self.events = []

        self.appeared()

    def print_info(self):
        status = "\033[92m[+]\033[0m" if self.active else "\033[91m[-]\033[0m"
        print("{} {} ({}) - {}".format(status, self.ip, self.mac, self.vendor))
        print("Hostname: {}".format(self.hostname))
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

        for ev in EVENTS:
            if ev.trigger(event, self):
                ev.execute()
