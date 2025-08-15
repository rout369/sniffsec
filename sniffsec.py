
import argparse
import logging
from collections import defaultdict
from utils.banner import show_initial_loading
from graph.graph import generate_graph_from_json
from detection.detect import arp_spoofing_detection, dns_spoofing_detection
from monitor.monitor import monitor_network_activity , packet_sniffer

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
stop_sniffing = False  # Global flag to stop sniffing

# Global counters
ip_counter = defaultdict(int)
protocol_counter = defaultdict(int)
 
def main():
    show_initial_loading()

    parser = argparse.ArgumentParser(
        description="Network Scanner Tool - Sniff traffic, detect ARP/DNS spoofing, and monitor activity.",
        epilog="""Usage examples:
        1. Packet sniffing:
           python sniffsec2.py --mode sniffer --interface Wi-Fi
        2. ARP spoofing detection:
           python sniffsec2.py --mode spoofing --interface wlan0
        3. DNS spoofing detection:
           python sniffsec2.py --mode dns --interface eth0
        4. Monitor and save network activity with graphs:
           python sniffsec2.py --mode monitor --interface Wi-Fi --output activity.json --packet-limit 300 --sample-rate 10
           (Generates an interactive 3D-effect pie chart for protocols and a 3D bar chart for IPs)
        """
    )

    parser.add_argument(
        '--mode',
        choices=['sniffer', 'dns', 'spoofing', 'monitor'],
        required=True,
        help="Choose the operation mode: 'sniffer', 'dns', 'spoofing', or 'monitor'."
    )
    parser.add_argument(
        '--interface',
        help="Specify the network interface to use (e.g., Wi-Fi, eth0, wlan0). Required for all modes.",
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
    parser.add_argument(
        '--sample-rate',
        type=int,
        default=10,
        help="Sample every nth packet to reduce CPU usage (default: 10, applicable to 'monitor' mode)."
    )

    args = parser.parse_args()

    if args.mode == 'sniffer':
        # packet_sniffer(args.interface)
        packet_sniffer(interface=args.interface, packet_limit=args.packet_limit or 100)
    elif args.mode == 'spoofing':
        arp_spoofing_detection(args.interface)
    elif args.mode == 'dns':
        dns_spoofing_detection(args.interface)
    elif args.mode == 'monitor':
        if not args.output:
            logging.error("Please specify an output file using --output for 'monitor' mode.")
            return
        monitor_network_activity(args.interface, args.output, args.packet_limit, args.sample_rate)

        if input("Do you want to generate graphs? (y/n): ").lower() == 'y':
            generate_graph_from_json(args.output)

if __name__ == '__main__':
    main()
