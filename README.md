# ip_spoofing
Repo for group 5 os network security.
Docker commands:



# Create the network
docker network create arp

docker run -it --rm --network=arp alpine

# Run the victim container
docker load < netsec_arp_victim

docker run -it --rm --name=netsec_arp_victim --network=arp netsec_arp_victim



# Build and Run the attacker container
docker build -t netsec_arp_attacker -f Dockerfile.attacker .

docker run -it --rm --name=netsec_arp_attacker \
    --network=arp                              \    # Attach to arp network
    --cap-add=net_raw                          \    # Add raw socket capability
    netsec_arp_attacker                        \
    ${attacker_mac_address}                    \    # Attacker MAC address
    ${victim_mac_address}                      \    # Victim MAC address
    ${gateway_mac_address}                     \    # Gateway MAC address
    ${attacker_ip_address}                     \    # Attacker IPv4 address
    ${victim_ip_address}                       \    # Victim IPv4 address
    ${gateway_ip_address}                           # Gateway IPv4 address
    
    
    docker run -it --rm --name=netsec_arp_attacker --network=arp --cap-add=net_raw netsec_arp_attacker 
