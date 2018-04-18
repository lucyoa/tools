from scapy.all import (
    Ether,
    ARP,
)


class ArpPkt(object):
    def __init__(self, pkt):
        # Ether
        self.dst = pkt[Ether].dst
        self.src = pkt[Ether].src
        self.type = pkt[Ether].type
        
        # ARP
        self.hardware_type = pkt[ARP].hwtype             # hwtype - hardware type - 2 bytes
        self.protocol_type = pkt[ARP].ptype              # ptype  - protocol type - 2 bytes
        self.hardware_address_length = pkt[ARP].hwlen    # hwlen  - hardware address length - 1 byte
        self.protocol_address_length = pkt[ARP].plen     # plen   - protocol address length - 1 byte
        self.opcode = pkt[ARP].op                        # op     - operation code - 2 bytes
        self.sender_hardware_address = pkt[ARP].hwsrc    # hwsrc  - sender's hardware address - 6 bytes
        self.sender_ip_address = pkt[ARP].psrc           # psrc   - sender's ip address - 4 bytes
        self.target_hardware_address = pkt[ARP].hwdst    # hwdst  - target's hardware address - 6 bytes
        self.target_ip_address = pkt[ARP].pdst           # pdst   - sender's ip address - 4 bytes

    def print_info(self):
        print("{} --> {} (Type: 0x{:x})".format(self.src, self.dst, self.type))

        print(self.summary())
        print("  Hardware Type: {}".format(self.hardware_type))
        print("  Protocol Type: 0x{:x}".format(self.protocol_type))
        print("  Hardware Address Length: {}".format(self.hardware_address_length))
        print("  Protocol Address Length: {}".format(self.protocol_address_length))
        print("  Opcode: 0x{:x} ({})".format(self.opcode, self.resolve_opcode(self.opcode)))
        print("  Sender's Hardware Address: {}".format(self.sender_hardware_address))
        print("  Sender's IP Address: {}".format(self.sender_ip_address))
        print("  Target's Hardware Address: {}".format(self.target_hardware_address))
        print("  Target's IP Addres: {}".format(self.target_ip_address))
        print()

    def summary(self):
        msg = "???"

        if self.opcode == 0x1:
            msg = "{}: Who has IP address {}".format(self.sender_ip_address, self.target_ip_address)
        elif self.opcode == 0x2:
            msg = "{}: Hardware address of {} is {}".format(self.sender_ip_address, self.sender_ip_address, self.sender_hardware_address)
        elif self.opcode == 0x3:
            msg = "{}: RARP Request".format(self.sender_hardware_address)
        elif self.opcode == 0x4:
            msg = "{}: RARP Response".format(self.sender_hardware_address)

        return msg

    @staticmethod
    def resolve_opcode(opcode):
        return {
            0x1: "ARP Request",
            0x2: "ARP Response",
            0x3: "RARP Request",
            0x4: "RARP Response",
        }.get(opcode, "Unknown")
