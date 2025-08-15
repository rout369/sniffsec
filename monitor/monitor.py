from collections import defaultdict
import time
import logging
from scapy.all import sniff, IP, ARP, TCP, UDP, DNS
from utils.signal import get_signal_strength, update_live_table, packet_callback
import json


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

def monitor_network_activity(interface, output_file, packet_limit=None, sample_rate=10):
    """Monitor network activity with performance optimizations."""
    global stop_sniffing
    ip_counter = defaultdict(int)
    protocol_counter = defaultdict(int)
    total_packets = [0]
    temp_ip_counter = defaultdict(int)
    temp_protocol_counter = defaultdict(int)
    last_update_time = time.time()
    update_interval = 2.0  # Update table every 2 seconds

    def update_counters_and_table():
        nonlocal ip_counter, protocol_counter, temp_ip_counter, temp_protocol_counter
        for ip, count in temp_ip_counter.items():
            ip_counter[ip] += count
        for protocol, count in temp_protocol_counter.items():
            protocol_counter[protocol] += count
        signal_strength = get_signal_strength(interface)
        update_live_table(ip_counter, protocol_counter, signal_strength)
        temp_ip_counter.clear()
        temp_protocol_counter.clear()

    try:
        logging.info(f"Monitoring network activity on {interface} with sample rate {sample_rate}...")
        while not stop_sniffing:
            sniff(
                iface=interface,
                prn=lambda pkt: packet_callback(pkt, ip_counter, protocol_counter, packet_limit, total_packets, sample_rate, temp_ip_counter, temp_protocol_counter),
                timeout=update_interval,
                store=0
            )
            current_time = time.time()
            if current_time - last_update_time >= update_interval:
                update_counters_and_table()
                last_update_time = current_time
            if packet_limit and total_packets[0] >= packet_limit:
                logging.info(f"Packet limit of {packet_limit} reached. Stopping monitoring.")
                stop_sniffing = True
                break
    except KeyboardInterrupt:
        logging.info("Monitoring stopped by user.")
    finally:
        update_counters_and_table()
        save_data_to_file(ip_counter, protocol_counter, output_file)
        logging.info(f"Total packets captured: {total_packets[0]}")


def explain_packet(packet):
    """Return a human-readable explanation of a packet."""
    if packet.haslayer(DNS) and packet.haslayer(IP):
        try:
            qname = packet[DNS].qd.qname.decode()
            if packet[DNS].qr == 0:
                return f"[🔍 DNS] {packet[IP].src} asked for {qname}"
            else:
                answers = [ans.rdata for ans in packet[DNS].an] if packet[DNS].ancount > 0 else []
                return f"[🧠 DNS-RESP] {qname} → {', '.join(map(str, answers))}"
        except:
            return "[⚠️ DNS] Malformed DNS packet"

    elif packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 1:
            return f"[🔎 ARP-REQ] Who has {arp.pdst}? Tell {arp.psrc}"
        elif arp.op == 2:
            return f"[📢 ARP-REP] {arp.psrc} is at {arp.hwsrc}"

    elif packet.haslayer(TCP) and packet.haslayer(IP):
        flags = packet.sprintf("%TCP.flags%")
        return f"[⚙️ TCP] {packet[IP].src}:{packet[TCP].sport} → {packet[IP].dst}:{packet[TCP].dport} Flags: {flags}"

    elif packet.haslayer(UDP) and packet.haslayer(IP):
        return f"[📡 UDP] {packet[IP].src}:{packet[UDP].sport} → {packet[IP].dst}:{packet[UDP].dport}"

    elif packet.haslayer(IP):
        return f"[📦 IP] {packet[IP].src} → {packet[IP].dst} Proto: {packet[IP].proto}"

    return "[❓ UNKNOWN] Could not interpret this packet"


def packet_sniffer(interface, packet_limit=100):
    """Capture and display packet information on the given network interface."""
    captured_packets = []

    def packet_callback(packet):
        # Log the summary
        logging.info(f"Packet: {packet.summary()}")

        # Print human-friendly explanation
        explanation = explain_packet(packet)
        if explanation:
            print(explanation)
            captured_packets.append((packet, explanation))

    logging.info(f"Sniffing up to {packet_limit} packets on interface {interface}...")

    # 🔄 Always runs: either stops by limit or user interrupt
    try:
        sniff(iface=interface, prn=packet_callback, store=False, count=packet_limit)
    except KeyboardInterrupt:
        logging.info("Packet sniffing stopped by user.")

    # ✅ Moved outside of try/except
    print("\n[🔍] Packet capture complete. You can now filter packets.")
    while True:
        filter_choice = input("Enter filter (dns, arp, tcp, udp, ip, all, quit): ").strip().lower()

        if filter_choice == "quit":
            print("[🚪] Exiting filter mode.")
            break

        filtered = []
        for pkt, expl in captured_packets:
            if filter_choice == "all":
                filtered.append(expl)
            elif filter_choice == "dns" and pkt.haslayer(DNS):
                filtered.append(expl)
            elif filter_choice == "arp" and pkt.haslayer(ARP):
                filtered.append(expl)
            elif filter_choice == "tcp" and pkt.haslayer(TCP):
                filtered.append(expl)
            elif filter_choice == "udp" and pkt.haslayer(UDP):
                filtered.append(expl)
            elif filter_choice == "ip" and pkt.haslayer(IP) and not pkt.haslayer(DNS) and not pkt.haslayer(TCP) and not pkt.haslayer(UDP):
                filtered.append(expl)

        print(f"\n[📦] Showing {len(filtered)} packets matching: {filter_choice.upper()}\n")
        for item in filtered:
            print(item)
