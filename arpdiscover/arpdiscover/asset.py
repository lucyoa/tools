from arpdiscover.utils import vendor_lookup


class Asset(object):
    def __init__(self, mac, ip):
        self.mac = mac
        self.ip = ip
        self.vendor = vendor_lookup(mac)

    def print_info(self):
        print("{} - {} ({})".format(self.ip, self.mac, self.vendor))
