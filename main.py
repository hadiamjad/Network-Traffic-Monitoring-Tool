from scapy.all import *
import argparse
import os

#sets up a single command line argument to be received which the
#duration of capture (time bin)
parser = argparse.ArgumentParser(description="Network Analysis")
parser.add_argument("-d", type=int, dest="duration", default=1)
args = parser.parse_args()

print(f"Trying to run tcpdump for {args.duration} seconds")

#there is no interface supplied which means we are capturing on
#all interfaces.
ret = os.system(f"sudo timeout {args.duration} tcpdump -w my.pcap")


#linux returns -1 on error and pid of terminated process on success.
#for windos things are different. So, if you are to run it on windows,
#change this.

if ret == -1:
    print("There was an error running the tcpdump command")
else:
    data = rdpcap("my.pcap")
    print("Number of packets:", len(data))


