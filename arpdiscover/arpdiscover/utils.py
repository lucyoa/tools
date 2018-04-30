VENDORS = {}

def load_vendors():
    with open("./arpdiscover/oui.dat", "r") as f:
        for line in f.readlines():
            line = line.strip()
            if line == "" or line.startswith("#"):
                continue

            mac, name = line.split(" ", 1)
            VENDORS[mac] = name
load_vendors()
del load_vendors


def vendor_lookup(mac):
    mac = "".join(mac.upper().split(":")[:3])
    if mac in VENDORS:
        return VENDORS[mac]

    return "Unknown"
