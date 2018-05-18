from scanner.port import Port, Protocol, State
from scapy.all import *


class Scanner(object):
    def __init__(self, target, ports):
        conf.verb = 0
        self.s = conf.L3socket(iface="lo0")

        self.target = target

        self.ports = ports
        self.scanned_ports = []

        self.timeout = 2

    def scan(self, technique):
        for port in self.ports.tcp:
            if technique == "tcp":
                self.tcp_scan(port)
            elif technique == "syn":
                self.syn_scan(port)
            elif technique == "null":
                self.null_scan(port)
            elif technique == "fin":
                self.fin_scan(port)
            elif technique == "xmas":
                self.xmas_scan(port)
            elif technique == "ack":
                self.ack_scan(port)

        for port in self.ports.udp:
            if technique == "udp":
                self.udp_scan(port)

        self.display()

    def display(self):
        if not self.scanned_ports:
            return

        num_spaces = max([len(port.get_port_str()) for port in self.scanned_ports]) + 1
        num_spaces2 = max([len(port.get_state()) for port in self.scanned_ports]) + 1

        if len(self.ports.tcp) + len(self.ports.udp) > 20: 
            filtered_ports = [port for port in self.scanned_ports if port.state != State.Closed]
        else:
            filtered_ports = [port for port in self.scanned_ports]

        sorted_ports = sorted(filtered_ports, key=lambda port: port.port_number)

        print("PORT{}STATE{}SERVICE".format(" " * (num_spaces - 4), " " * (num_spaces2 - 5)))
        for port in sorted_ports:
            port_str = port.get_port_str() 
            state = port.get_state()

            print("{}{}{}{}{}".format(
                port_str,
                " " * (num_spaces - len(port_str)),
                state,
                " " * (num_spaces2 - len(state)),
                port.service
            ))


    def tcp_scan(self, port_number):
        """ TCP connect scan

        -> SYN
        <- SYN/ACK - open
        <- RST - closed
        <- Timeouet - filtered
        """

        resp = self.s.sr1(IP(dst=self.target)/TCP(flags="S", dport=port_number, seq=100), timeout=self.timeout)

        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == "SA":
                resp = self.s.sr1(IP(dst=self.target)/TCP(flags="A", dport=port_number, seq=101, ack=resp[TCP].seq+1), timeout=self.timeout)
                resp = self.s.sr1(IP(dst=self.target)/TCP(flags="RA", dport=port_number, seq=102, ack=resp[TCP].seq+1), timeout=self.timeout)
                self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Open))
            elif resp[TCP].flags == "RA":
                self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Closed))
        else:
            self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Filtered))

    def syn_scan(self, port_number):
        """ SYN scan 

        -> SYN
        <- SYN/ACK - open 
        <- RST - closed
        <- Timeout - filtered
        """

        resp = self.s.sr1(IP(dst=self.target)/TCP(flags="S", dport=port_number), timeout=self.timeout)

        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == "SA":
                self.s.sr1(IP(dst=self.target)/TCP(flags="RA", dport=port_number), timeout=self.timeout)
                self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Open))
            elif resp[TCP].flags == "RA":
                self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Closed))
        else:
            self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Filtered))

    def null_scan(self, port_number):
        """ Null scan

        -> Null flags
        <- Timeout - open|filtered 
        <- RST - closed
        """

        resp = self.s.sr1(IP(dst=self.target)/TCP(flags="", dport=port_number), timeout=self.timeout)

        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == "RA":
                self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Closed))
        else:
            self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Open|State.Filtered))

    def fin_scan(self, port_number):
        """ Fin scan

        -> FIN
        <- Timeout - open|filtered
        <- RST - closed
        """

        resp = self.s.sr1(IP(dst=self.target)/TCP(flags="F", dport=port_number), timeout=self.timeout)
        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == "RA":
                self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Closed))
        else:
            self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Open|State.Filtered))

    def xmas_scan(self, port_number):
        """ XMas scan

        -> FIN/PSH/URG
        <- Timeout - open|filetered
        <- RST - closed
        """

        resp = self.s.sr1(IP(dst=self.target)/TCP(flags="UPF", dport=port_number), timeout=self.timeout)
        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == "RA":
                self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Closed))
        else:
            self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Open|State.Filtered))

    def ack_scan(self, port_number):
        """ ACK scan

        -> ACK
        <- RST - unfiltered
        <- Timeout - filetered
        """

        resp = self.s.sr1(IP(dst=self.target)/TCP(flags="A", dport=port_number), timeout=self.timeout)
        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == "R":
                self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Unfiltered))
        else:
            self.scanned_ports.append(Port(Protocol.TCP, port_number, State.Filtered))

    def udp_scan(self, port_number):
        """ UDP scan

        -> UDP packet
        <- None 3x times - Open|Filtered
        <- UDP packet - Open
        <- ICMP - Type:3 Code:3 - Closed
        <- ICMP - Type:3 Code:1|2|9|10|13 - Filtered
        """

        for _ in range(3):
            resp = self.s.sr1(IP(dst=self.target)/UDP(dport=port_number), timeout=self.timeout)
            if resp:
                break
        else:
            self.scanned_ports.append(Port(Protocol.UDP, port_number, State.Open|State.Filtered))
            return

        if resp.haslayer(UDP):
            self.scanned_ports.append(Port(Protocol.UDP, port_number, State.Open))

        elif resp.haslayer(ICMP):
            if resp[ICMP].type == 3 and resp[ICMP].code == 3:
                self.scanned_ports.append(Port(Protocol.UDP, port_number, State.Closed))

            elif resp[ICMP].type == 3 and resp[ICMP].code in [1,2,9,10,13]:
                self.scanned_ports.append(Port(Protocol.UDP, port_number, State.Filtered))
