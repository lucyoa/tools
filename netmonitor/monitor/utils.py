import importlib
import requests
import json
import dns.resolver, dns.reversename
from os import listdir


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


def lookup_dhcpv4(dhcpv4):
    url = "https://fingerbank.inverse.ca/api/v1/combinations/interogate?key=javascript-lib&dhcp_fingerprint={}".format(dhcpv4)
    response = requests.get(url, headers={"X-Fingerbank-Lib": "Inverse-Javascript-Lib"})

    if response:
        data = json.loads(response.text)       

        if "device" in data.keys() and "name" in data["device"].keys():
            return data["device"]["name"]

    return None

