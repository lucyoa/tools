# NetScan 

## Description
NetScan is network scanner (similar to NMAP) built in python3 and scapy library. It was created just for educational purposes, so for your work just use nmap :)

## Installation

Just clone the repo, make sure scapy is installed and start scanning!
```
python3 -m pip install scapy
python3 netscan.py 192.168.1.1 --syn
```

## Usage:
```
$ python3 netscan.py --help
usage: netscan.py [-h] [-sT] [-sS] [-sN] [-sF] [-sX] [-sA] [-sU]
                  [-p [PORTS [PORTS ...]]]
                  target

positional arguments:
  target

optional arguments:
  -h, --help            show this help message and exit
  -sT, --tcp            TCP Connect scan
  -sS, --syn            TCP Syn scan
  -sN, --null           TCP Null scan
  -sF, --fin            TCP Fin scan
  -sX, --xmas           TCP XMas scan
  -sA, --ack            TCP Ack scan
  -sU, --udp            UDP scan
  -p [PORTS [PORTS ...]], --ports [PORTS [PORTS ...]]
```
