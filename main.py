from scapy.all import *
import argparse
import os

def SystemCmd():
    #sets up a single command line argument to be received which the
    #duration of capture (time bin)
    parser = argparse.ArgumentParser(description="Network Analysis")
    parser.add_argument("-d", type=int, dest="duration", default=20)
    args = parser.parse_args()

    print(f"Trying to run tcpdump for {args.duration} seconds")

    #there is no interface supplied which means we are capturing on
    #all interfaces.
    ret = os.system(f"sudo timeout {args.duration} tcpdump -w my.pcap")



class packet:
    def __init__(self, s, d, p):
        self.src = s
        self.dst = d
        self.prt = p
    def print (self):
        print ("Source: ",self.src)
        print ("Destination: ",self.dst)
        print ("Protocol: ",self.prt)

def extract(protocol,data):
    lst = []
    print(protocol)   
    for pkt in data:
        if pkt.haslayer(protocol) == 1:
            lst.append(packet(pkt[protocol].fields['src'],pkt[protocol].fields['dst'],protocol))
    for obj in lst:
        obj.print()



def test():
    SystemCmd()
    data = rdpcap("my.pcap")
    extract(IP,data)


test()
