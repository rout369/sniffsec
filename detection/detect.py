import logging
from scapy.all import sniff, IP, ARP, TCP, UDP, DNS

def arp_spoofing_detection(interface):
    """Detect ARP spoofing by checking for duplicate ARP replies."""
    logging.info(f"Monitoring ARP traffic on {interface} for potential ARP spoofing...")
    ip_mac_map = {}

    def packet_callback(packet):
        if packet.haslayer(ARP):
            arp_packet = packet[ARP]
            if arp_packet.op == 2:
                ip = arp_packet.psrc
                mac = arp_packet.hwsrc
                if ip in ip_mac_map and ip_mac_map[ip] != mac:
                    logging.warning(f"ARP Spoofing detected: IP {ip} is now associated with MAC {mac}, was previously associated with {ip_mac_map[ip]}")
                else:
                    ip_mac_map[ip] = mac

    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        logging.info("ARP spoofing detection stopped by user.")

def dns_spoofing_detection(interface):
    """Detect DNS spoofing by checking for mismatched IP responses to DNS queries."""
    logging.info(f"Monitoring DNS traffic on {interface} for potential DNS spoofing...")
    dns_records = {}

    def packet_callback(packet):
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dns_query = packet[DNS].qd.qname.decode('utf-8') if packet[DNS].qd else None
            dns_response_ip = packet[IP].src
            if dns_query:
                if dns_query in dns_records:
                    if dns_records[dns_query] != dns_response_ip:
                        logging.warning(f"DNS Spoofing detected: Query {dns_query} responded by {dns_response_ip}, but was previously responded by {dns_records[dns_query]}")
                else:
                    dns_records[dns_query] = dns_response_ip

    try:
        sniff(iface=interface, filter="udp port 53", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        logging.info("DNS spoofing detection stopped by user.")