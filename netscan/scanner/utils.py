class PortsList:
    def __init__(self, tcp, udp):
        self.tcp = tcp
        self.udp = udp


def parse_ports(ports_args):
    tcp_ports = []
    udp_ports = []

    for port_string in ports_args:
        port_string = port_string.replace(" ", "")
        if port_string.startswith("T:"):
            tcp_ports += [int(port) for port in port_string[2:].split(",")]
        elif port_string.startswith("U:"):
            udp_ports += [int(port) for port in port_string[2:].split(",")]
        else:
            tcp_ports += [int(port) for port in port_string.split(",")]

    return PortsList(
        tcp=list(set(tcp_ports)),
        udp=list(set(udp_ports)),
    )


SERVICES = []
def load_services():
    with open("./scanner/services.txt") as f:
        for line in f.readlines():
            line = line.strip()
            service, port, frequency = line.split(" ")

            SERVICES.append((port, service, float(frequency)))
load_services()
del load_services


def lookup_service(port):
    for service in SERVICES:
        if port == service[0]:
            return service[1] 

    return None


def get_top_ports(num):
    ports = sorted(SERVICES, key=lambda port: port[2], reverse=True)
    tcp_ports = [int(port[0].replace("/tcp", "")) for port in ports[:num] if "/tcp" in port[0]]
    udp_ports = [int(port[0].replace("/udp", "")) for port in ports[:num] if "/udp" in port[0]]

    return PortsList(
        tcp=tcp_ports,
        udp=udp_ports,
    )
