import subprocess
import platform
from rich.console import Console
from rich.table import Table
from scapy.all import sniff, IP, ARP, TCP, UDP, DNS
import logging

console = Console()

def get_signal_strength(interface):
    """Get Wi-Fi signal strength based on OS."""
    os_type = platform.system()
    try:
        if os_type == "Windows":
            command = f"netsh wlan show interfaces"
            result = subprocess.check_output(command, shell=True, text=True)
            for line in result.split("\n"):
                if "Signal" in line:
                    signal_strength = line.split(":")[1].strip()
                    return f"{signal_strength}"
        elif os_type == "Linux":
            command = f"iwconfig {interface}"
            result = subprocess.check_output(command, shell=True, text=True)
            for line in result.split("\n"):
                if "Signal level" in line:
                    signal_strength = line.split("Signal level=")[1].split()[0]
                    return f"{signal_strength} dBm"
        else:
            return "Not Available (Unsupported OS)"
    except subprocess.CalledProcessError:
        return "Not Available (Interface not Wi-Fi or down)"
    except Exception as e:
        return f"Error: {str(e)}"
    

def update_live_table(ip_counter, protocol_counter, signal_strength):
    """Update live data table with unique IPs, protocol counts, and signal strength."""
    table = Table(title="Network Packet Statistics")
    table.add_column("Unique IP", justify="center")
    table.add_column("Count", justify="center")
    table.add_column("Protocol", justify="center")

    for ip, count in ip_counter.items():
        table.add_row(ip, str(count), "-")
    for protocol, count in protocol_counter.items():
        table.add_row("-", "-", f"{protocol}: {count}")
    table.add_row("Signal Strength", signal_strength, "-")

    console.clear()
    console.print(table)

def packet_callback(packet, ip_counter, protocol_counter, packet_limit, total_packets, sample_rate, temp_ip_counter, temp_protocol_counter):
    global stop_sniffing
    if stop_sniffing:
        return False

    total_packets[0] += 1  # Increment packet count

    # Stop sniffing when packet limit is reached
    if packet_limit and total_packets[0] >= packet_limit:
        logging.info(f"Packet limit of {packet_limit} reached. Stopping monitoring.")
        stop_sniffing = True
        return False

    # Sample packets: process every nth packet
    if total_packets[0] % sample_rate != 0:
        return True  # Skip processing this packet

    # Count unique IPs
    if packet.haslayer(IP):
        temp_ip_counter[packet[IP].src] += 1
        temp_ip_counter[packet[IP].dst] += 1

    # Count protocols
    if packet.haslayer(ARP):
        temp_protocol_counter["ARP"] += 1
    elif packet.haslayer(TCP):
        temp_protocol_counter["TCP"] += 1
    elif packet.haslayer(UDP):
        temp_protocol_counter["UDP"] += 1

    return True