#!/usr/bin/env python3

import socket
import struct
import glob
import json


PORT = 53
IP = "127.0.0.1"


def load_zones():
    json_zone = {}

    zonefiles = glob.glob("zones/*.zone")
    for zonefile in zonefiles:
        with open(zonefile, "r") as fp:
            data = json.load(fp)
            zone_name = data["$origin"]
            json_zone[zone_name] = data

    return json_zone


zone_data = load_zones()
print(zone_data)

def get_flags(flags):
    byte1, byte2 = struct.unpack(">BB", flags)

    QR = "1"
    OPCODE = ""
    for bit in range(1, 5):
        OPCODE += str(byte1 & (1<<bit))

    AA = "1"
    TC = "0"
    RD = "0"

    RA = "0" 
    Z = "000"
    RCODE = "0000"

    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder="big") + int(RA+Z+RCODE, 2).to_bytes(1, byteorder="big")


def get_question_domain(data):
    state = 0

    domain_parts = []
    print(data)

    pos = 0
    while data[pos] != 0x0 and pos < len(data):
        length = data[pos]
        start = pos + 1
        finish = start + length
        pos = finish 

        domain = str(data[start: finish], "utf-8")
        domain_parts.append(domain)

    question_type = data[finish+1: finish+3]

    return (domain_parts, question_type)
        

def getzone():
    pass


def getrecs(data):
    domain, question_type = get_question_domain(data)

    if question_type == b"\x00\x01":
        qt = "A"

def build_response(data):
    TransactionID, = struct.unpack(">H", data[:2])

    # Get the flags
    Flags = get_flags(data[2:4])


    # Question Count
    QDCOUNT = b"\x00\x01"

    domain = get_question_domain(data[12:])
    print(domain)


    return b"Hello"



def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    
    while True:
        data, addr = sock.recvfrom(512)

        r = build_response(data)
        sock.sendto(r, addr)

    sock.close()

if __name__ == "__main__":
    main()
