import dns.resolver, dns.reversename
from os import listdir
import importlib


VENDORS = {}
EVENTS = []

def load_vendors():
    with open("./monitor/oui.dat", "r") as f:
        for line in f.readlines():
            line = line.strip()
            if line == "" or line.startswith("#"):
                continue
    
            mac, name = line.split(" ", 1)
            VENDORS[mac] = name
load_vendors()
del load_vendors


def load_events():
    files = [i for i in listdir("./events/") if i.endswith(".py")]
    
    for f in files:
        path = "events." + f.split(".")[0]
        EVENTS.append(importlib.import_module(path).Event())
load_events()
del load_events


def vendor_lookup(mac):
    mac = "".join(mac.upper().split(":")[:3])
    if mac in VENDORS:
        return VENDORS[mac]

    return "Unknown"


def resolve_ip(ip):
    my_resolver = dns.resolver.Resolver()
    reversename = dns.reversename.from_address(ip) 

    hostname = "Unknown"
    try:
        hostname = str(my_resolver.query(reversename, "PTR")[0])[:-1]
    except Exception:
        pass

    return hostname
