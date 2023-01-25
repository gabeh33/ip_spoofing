#!/usr/bin/env python3
from multiprocessing import Process

#import coloredlogs
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP, TCP, IP
from scapy.layers.l2 import Ether, ARP

INTERFACE = "eth0"


class TCPServerState:
    LISTEN = 0,
    SYN_RECIEVED = 1,
    ESTABLISHED = 2,
    # graceful close
    FIN_WAIT_1



def arp_main(src_hw_addr: str, target_hw_addr: str, gw_hw_addr: str, target_ip_addr: str, gw_ip_address: str) -> None:
    while True:
        p = Ether(dst=target_hw_addr, src=src_hw_addr) / ARP(op="")
        sendp(p)
        time.sleep(1.0)


def on_dns_packet(p: Packet) -> None:
    logging.info(f"forwarding DNS request")
    # print(p[DNS])
    response = sr1(IP(src=p[IPv6].dst, dst = p[IPv6].src)/UDP(src=p[UDP].dport, dst=p[UDP].sport)
            / Ether(src=p[Ethernet].dst, dst=p[Ethernet].src)
            / DNS(qr=1, id=p[DNS].id, an=DNSRR()/DNSRR(rdata=("test"))))
    print("attempting to show packet", flush=True)
    response.show()

def on_http_packet(p: Packet) -> None:
    global http_server_state
    assert IP in p
    assert TCP in p
    assert p[TCP].dport == 1200

    if http_server_state== TCPServerState.LISTEN:
        if p[TCP].flags == 'S':
            r = Ether() / IP() / TCP()
            sendp(r, iface=INTERFACE)
            pass
        else:
            logging.error("espected SYN packet")

    elif http_server_state == TCPServerState.SYN_RECIEVED:
        pass
    pass

def on_packet(p: Packet) -> None:
    if TCP in p and p[TCP].dport == 1200:
        on_http_packet(p)
    print("received a packet!")
    if UDP in p and DNS in p:
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
