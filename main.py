import scapy.all as scapy
from scapy.layers.inet import TCP, UDP, IP, Ether
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.rtp import RTP
import argparse
import os


def getFile():
    # sets up two command line arguments to be received which the
    # duration of capture (time bin).
    parser = argparse.ArgumentParser(description="Network Analysis")
    parser.add_argument("-d", type=int, dest="duration", default=20)
    parser.add_argument("-f", type=str, dest="file", required=False)

    args = parser.parse_args()
    defaultFileName = "private.temp.pcap"
    # there is no interface supplied which means we are capturing on
    # all interfaces.
    if args.file is None:
        print(f"Trying to run tcpdump for {args.duration} seconds")
        ret = os.system(f"sudo timeout {args.duration} tcpdump -w {defaultFileName}")
        if ret == 0:
            raise RuntimeError("Capture unsuccessful")
    return args.file if args.file is not None else defaultFileName


class packet:
    def __init__(self, s, d, p):
        self.src = s
        self.dst = d
        self.prt = p

    def print(self):
        print("Source: ", self.src)
        print("Destination: ", self.dst)
        print("Protocol: ", self.prt)


def extract(data):
    scapyProtocols = [Ether, IP, IPv6, UDP, TCP, DNS, RTP, HTTP]
    returner = {protocol.__name__: [] for protocol in scapyProtocols}
    returner["HTTPS"] = []
    returner["FTP"] = []
    returner["VoIP"] = []
    for pkt in data:
        for protocol in scapyProtocols:
            if pkt.haslayer(protocol):
                returner[protocol.__name__].append(pkt)
        if pkt.haslayer(TCP) and (
            pkt[TCP].fields["sport"] == 443 or pkt[TCP].fields["dport"] == 443
        ):
            returner["HTTPS"].append(pkt)
        if pkt.haslayer(TCP) and (
            pkt[TCP].fields["sport"] == 20
            or pkt[TCP].fields["dport"] == 20
            or pkt[TCP].fields["sport"] == 21
            or pkt[TCP].fields["dport"] == 21
        ):
            returner["FTP"].append(pkt)
        if (
            pkt.haslayer(TCP)
            and (pkt[TCP].fields["sport"] == 5060 or pkt[TCP].fields["dport"] == 5060)
        ) or (
            pkt.haslayer(UDP)
            and (pkt[UDP].fields["sport"] == 5060 or pkt[UDP].fields["dport"] == 5060)
        ):
            returner["VoIP"].append(pkt)
    return returner


def test():
    data = scapy.rdpcap(getFile())
    results = extract(data)
    for protocol in results:
        print(f"{protocol}: {len(results[protocol])}")


test()
