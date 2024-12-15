

from tqdm import tqdm
import sys
import ipaddress
import argparse
import time
import logging
import subprocess
import json
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from scapy.all import sniff, IP, ARP, TCP, UDP, DNS
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import numpy as np

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
# Logo as a simple text block
logo = r"""
                        ┏┓  •┏┏┏┓     
                        ┗┓┏┓┓╋╋┗┓┏┓┏  
                        ┗┛┛┗┗┛┛┗┛┗ ┗                                            \
                                                                                \ \
                                                                  __________.>))| |   Internet
[@] createor (👨‍💻 $ :-> Biswajit                               |              / /
[@] version  (🛠️    $ :->  1.0v                                  |              /
[@] git_hub  (🐙     $ :-> https://github.com/rout369            |
                                                                 |
  ___   _      ___   _      ___   _      ___   _      ___   _    |          
 [(_)] |=|    [(_)] |=|    [(_)] |=|    [(_)] |=|    [(_)] |=|   |
  '-`  |_|     '-`  |_|     '-`  |_|     '-`  |_|     '-`  |_|   |
 /mmm/  /     /mmm/  /     /mmm/  /     /mmm/  /     /mmm/  /    |
       |____________|____________|____________|____________|_____|
                             |            |            |
                         ___  \_      ___  \_      ___  \_               
                        [(_)] |=|    [(_)] |=|    [(_)] |=|             
                         '-`  |_|     '-`  |_|     '-`  |_|              
                        /mmm/        /mmm/        /mmm/       

<<<<<<<<<<--------------------------------------------------------------------------------------->>>>>>>>>>                              
 """
               
# Show the loading bar and then display the logo
def show_initial_loading():
    for _ in tqdm(range(100), desc="Loading", ncols=100):
        time.sleep(0.02)  # Simulate loading time
    print(" ")
    print(logo)
    time.sleep(1)  # Delay for a moment before showing help

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# Rich console for real-time logging
console = Console()

stop_sniffing = False  # Global flag to stop sniffing

# Global counters
ip_counter = defaultdict(int)
protocol_counter = defaultdict(int)


def get_signal_strength(interface):
    """Get the Wi-Fi signal strength on Windows."""
    try:
        command = f"netsh wlan show interfaces"
        result = subprocess.check_output(command, shell=True, text=True)

        # Find the line that contains the signal strength
        for line in result.split("\n"):
            if "Signal" in line:
                signal_strength = line.split(":")[1].strip()
                return f"{signal_strength} dBm"
    except Exception as e:
        return f"Error: {str(e)}"


def update_live_table(ip_counter, protocol_counter, signal_strength):
    """Update the live data table with unique IPs, protocol counts, and signal strength."""
    table = Table(title="Network Packet Statistics")

    table.add_column("Unique IP", justify="center")
    table.add_column("Count", justify="center")
    table.add_column("Protocol", justify="center")

    # Add IPs and protocol counts to the table
    for ip, count in ip_counter.items():
        table.add_row(ip, str(count), "-")

    for protocol, count in protocol_counter.items():
        table.add_row("-", "-", f"{protocol}: {count}")

    # Add signal strength
    table.add_row("Signal Strength", signal_strength, "-")

    # Clear previous table and display the new one
    console.clear()
    console.print(table)


def packet_callback(packet, ip_counter, protocol_counter, packet_limit, total_packets):
    global stop_sniffing
    if stop_sniffing:
        return False

    total_packets[0] += 1  # Increment packet count

    # Stop sniffing when the packet limit is reached
    if packet_limit and total_packets[0] >= packet_limit:
        logging.info(f"Packet limit of {packet_limit} reached. Stopping monitoring.")
        stop_sniffing = True
        return False

    # Count unique IPs
    if packet.haslayer(IP):
        ip_counter[packet[IP].src] += 1
        ip_counter[packet[IP].dst] += 1

    # Count protocols
    if packet.haslayer(ARP):
        protocol_counter["ARP"] += 1
    elif packet.haslayer(TCP):
        protocol_counter["TCP"] += 1
    elif packet.haslayer(UDP):
        protocol_counter["UDP"] += 1

    # Update live table with signal strength and packet stats
    signal_strength = get_signal_strength("Wi-Fi")  # Replace with your network interface
    update_live_table(ip_counter, protocol_counter, signal_strength)


def save_data_to_file(ip_counter, protocol_counter, output_file):
    """Save data to a file in JSON format."""
    data = {
        "ip_counter": dict(ip_counter),
        "protocol_counter": dict(protocol_counter),
    }
    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
        logging.info(f"Data saved to {output_file}")
    except Exception as e:
        logging.error(f"Failed to save data: {e}")


def generate_graph_from_json(json_file):
    """Generate graphs from the JSON file, including a 2D line graph and 3D donut chart."""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)

        ip_counts = list(data['ip_counter'].values())  # Unique IP counts
        protocol_counts = data['protocol_counter']  # Protocol counts
        labels = list(protocol_counts.keys())
        sizes = list(protocol_counts.values())

        fig = plt.figure(figsize=(14, 7))

        # 2D Line Graph for Unique IP Counts Over Time
        ax1 = fig.add_subplot(121)
        ax1.plot(range(len(ip_counts)), ip_counts, marker='o', color='blue')
        ax1.set_title("Unique IP Count Over Time")
        ax1.set_xlabel("Time (Index)")
        ax1.set_ylabel("Count")
        ax1.grid(True)

        # 3D Donut Chart for Protocol Distribution
        ax2 = fig.add_subplot(122, projection='3d')

        sizes = np.array(sizes)
        total_size = sizes.sum()
        proportions = sizes / total_size
        start_angle = 90  # Start from the top
        width = 0.3  # Donut thickness
        cmap = plt.get_cmap("tab20c")
        colors = [cmap(i / len(sizes)) for i in range(len(sizes))]

        # Create the 3D effect for the donut chart
        for i, (prop, color, label) in enumerate(zip(proportions, colors, labels)):
            theta_start = start_angle
            theta_end = start_angle - (360 * prop)
            start_angle = theta_end

            # Define the "donut" shape
            theta = np.linspace(np.radians(theta_start), np.radians(theta_end), 100)
            z = np.linspace(0, 0.3, 2)  # 3D height
            theta, z = np.meshgrid(theta, z)
            x = np.cos(theta)
            y = np.sin(theta)

            ax2.plot_surface(
                x, y, z,
                color=color, edgecolor='k', alpha=0.8,
                label=label
            )

        # Customize the 3D donut chart
        ax2.set_title("3D Protocol Distribution (Donut)", pad=30)
        ax2.set_box_aspect([1, 1, 0.5])  # Flattened view
        ax2.legend(labels, loc="upper left", bbox_to_anchor=(1.05, 0.9))
        ax2.axis("off")  # Hide axes for a clean chart

        # Display the charts
        plt.tight_layout()
        plt.show()

    except Exception as e:
        logging.error(f"Failed to generate graph: {e}")


def monitor_network_activity(interface, output_file, packet_limit=None):
    """Monitor network activity."""
    global stop_sniffing

    ip_counter = defaultdict(int)
    protocol_counter = defaultdict(int)
    total_packets = [0]  # Using a mutable object to pass by reference

    try:
        logging.info(f"Monitoring network activity on {interface}...")
        sniff(
            iface=interface,
            prn=lambda pkt: packet_callback(pkt, ip_counter, protocol_counter, packet_limit, total_packets),
            stop_filter=lambda x: stop_sniffing,  # Stop sniffing if the flag is set
            store=0
        )
    except KeyboardInterrupt:
        logging.info("Monitoring stopped by user.")

    logging.info(f"Total packets captured: {total_packets[0]}")

    # Save the captured data to the output file
    save_data_to_file(ip_counter, protocol_counter, output_file)


# Packet Sniffer
def packet_sniffer(interface):
    """Capture and display packet information on the given network interface."""
    def packet_callback(packet):
        logging.info(f"Packet: {packet.summary()}")

    logging.info(f"Sniffing packets on interface {interface}...")

    try:
        # Simulate packet sniffing with a loading bar
        for _ in tqdm(range(100), desc="Sniffing packets", ncols=100):
            time.sleep(0.1)  # Simulate processing
        
        # Actual sniffing starts after the simulated part
        sniff(iface=interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        logging.info("Packet sniffing stopped by user.")

# Network Traffic Analyzer
def arp_spoofing_detection(interface):
    """Detect ARP spoofing by checking for duplicate ARP replies."""
    logging.info(f"Monitoring ARP traffic on {interface} for potential ARP spoofing...")
    ip_mac_map = {}  # To store IP to MAC address mapping

    def packet_callback(packet):
        if packet.haslayer(ARP):
            arp_packet = packet[ARP]
            if arp_packet.op == 2:  # ARP reply
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


# Main function to parse arguments and run corresponding functions
def main():
    show_initial_loading()  # Display loading and logo first

    parser = argparse.ArgumentParser(
        description="Network Scanner Tool - Sniff traffic, detect ARP/DNS spoofing, and monitor activity.",
        epilog="""Usage examples:
        1. Packet sniffing:
           python cron.py --mode sniffer --interface eth0
        2. ARP spoofing detection:
           python cron.py --mode spoofing --interface wlan0
        3. DNS spoofing detection:
           python cron.py --mode dns --interface eth0
        4. Monitor and save network activity to a file:
           python cron.py --mode monitor --interface wlan0 --output activity.json --packet-limit 500
        """
    )

    # Add arguments
    parser.add_argument(
        '--mode',
        choices=['sniffer', 'dns', 'spoofing', 'monitor'],
        required=True,
        help="Choose the operation mode: "
             "'sniffer' to capture and log packets, "
             "'dns' for DNS spoofing detection, "
             "'spoofing' for ARP spoofing detection, "
             "'monitor' to analyze and save network traffic."
    )
    parser.add_argument(
        '--interface',
        help="Specify the network interface to use (e.g., eth0, wlan0). Required for all modes.",
        required=True
    )
    parser.add_argument(
        '--output',
        help="File to save monitored network activity in JSON format (required for 'monitor' mode).",
        required=False
    )
    parser.add_argument(
        '--packet-limit',
        type=int,
        help="Limit the number of packets to capture (optional, applicable to 'monitor' mode)."
    )

    # Parse the arguments
    args = parser.parse_args()

    # Handle each mode
    if args.mode == 'sniffer':
        packet_sniffer(args.interface)
    elif args.mode == 'spoofing':
        arp_spoofing_detection(args.interface)
    elif args.mode == 'dns':
        dns_spoofing_detection(args.interface)
    elif args.mode == 'monitor':
        if not args.output:
            logging.error("Please specify an output file using --output for 'monitor' mode.")
            return
        monitor_network_activity(args.interface, args.output, args.packet_limit)

        if input("Do you want to generate graphs? (y/n): ").lower() == 'y':
            generate_graph_from_json(args.output)


if __name__ == '__main__':
    main()
