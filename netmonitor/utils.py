import dns.resolver, dns.reversename


def resolve_ip(ip):
    my_resolver = dns.resolver.Resolver()
    reversename = dns.reversename.from_address(ip) 

    hostname = "Unknown"
    try:
        hostname = str(my_resolver.query(reversename, "PTR")[0])[:-1]
    except Exception:
        pass

    return hostname


VENDORS = {}

with open("oui.dat", "r") as f:
    for line in f.readlines():
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue

        mac, name = line.split(" ", 1)
        VENDORS[mac] = name


def vendor_lookup(mac):
    mac = "".join(mac.upper().split(":")[:3])
    if mac in VENDORS:
        return VENDORS[mac]

    return "Unknown"
