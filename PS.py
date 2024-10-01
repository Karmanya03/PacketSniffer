from scapy.all import *

def packet_callback(packet):
    with open("packets.txt", "a") as f:
        f.write(packet.show(dump=True) + "\n")

sniff(prn=packet_callback, store=0)
