from scanner.utils import lookup_service


class Port:
    def __init__(self, protocol, port_number, state):
        self.protocol = protocol
        self.port_number = port_number
        self.state = state 
        self.service = lookup_service(self.get_port_str())

    def get_port_str(self):
        return "{}/{}".format(self.port_number, self.protocol)

    def get_state(self):
        if self.state == 0x1: 
            return "open" 
        elif self.state == 0x2:
            return "closed"
        elif self.state == 0x4:
            return "filtered"
        elif self.state == 0x5:
            return "open|filtered"
        elif self.state == 0x8:
            return "unfiltered"


class Protocol:
    TCP = "tcp"
    UDP = "udp"


class State:
    Open = 0x1
    Closed = 0x2
    Filtered = 0x4
    Unfiltered = 0x8 
