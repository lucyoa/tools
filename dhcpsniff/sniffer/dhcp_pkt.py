from scapy.all import (
    BOOTP,
    DHCP
)


class DHCPPkt(object):
    def __init__(self, pkt):

        # BOOTP
        self.op = pkt[BOOTP].op             # opcode - 1 byte
        self.htype = pkt[BOOTP].htype       # hardware type - 1 byte
        self.hlen = pkt[BOOTP].hlen         # hardware address length - 1 byte
        self.hops = pkt[BOOTP].hops         # hops - 1 byte
        self.xid = pkt[BOOTP].xid           # xid - transaction id - 4 bytes
        self.secs = pkt[BOOTP].secs         # secs - 2 bytes
        self.flags = pkt[BOOTP].flags       # flags - 2 bytes
        self.ciaddr = pkt[BOOTP].ciaddr     # ciaddr - client's IP address - 4 bytes 
        self.yiaddr = pkt[BOOTP].yiaddr     # yiaddr - your IP address - 4 bytes
        self.siaddr = pkt[BOOTP].siaddr     # siaddr - server's IP address - 4 bytes 
        self.giaddr = pkt[BOOTP].giaddr     # giaddr - gateway's IP address - 4 bytes
        self.chaddr = pkt[BOOTP].chaddr     # chaddr - client's hardware address - max 16 bytes
        self.sname = pkt[BOOTP].sname       # sname - server's host name - max 64 bytes
        self.file = pkt[BOOTP].file         # file - run server's name - max 128 bytes

        # DHCP
        self.options = pkt[DHCP].options    # dhcp options

    def print_info(self):
        print("---------------------------------")
        print("  OP: {} ({})".format(self.op, self.resolve_op(self.op)))
        print("  Htype: {}".format(self.htype))
        print("  Hlen: {}".format(self.hlen))
        print("  Hops: {}".format(self.hops))
        print("  Xid: {}".format(self.xid))
        print("  Secs: {}".format(self.secs))
        print("  Flags: {}".format(self.flags))
        print("  Ciaddr: {}".format(self.ciaddr))
        print("  Yiaddr: {}".format(self.yiaddr))
        print("  Siaddr: {}".format(self.siaddr))
        print("  Giaddr: {}".format(self.giaddr))
        print("  Chaddr: {}".format(self.chaddr))
        print("  Sname: {}".format(self.sname))
        print("  File: {}".format(self.file))

        print("  Options:")
        for option in self.options:
            if option[0] == "e":
                break

            if option[0] == "message-type":
                print("    {}: {} ({})".format(option[0], option[1], self.resolve_msg_type(option[1])))
            else:
               print("    {}: {}".format(option[0], option[1]))
        print()

    @staticmethod
    def resolve_op(op):
        return {
            0x1: "DHCP Request",
            0x2: "DHCP Response",
        }.get(op, "Unknown")

    @staticmethod
    def resolve_msg_type(message_type):
        return {
            0x1: "DHCP Discover",
            0x2: "DHCP Offer",
            0x3: "DHCP Request",
            0x4: "DHCP Decline",
            0x5: "DHCP ACK",
            0x6: "DHCP NAK",
            0x7: "DHCP Release",
            0x8: "DHCP Inform",
        }.get(message_type, "Unknown")
