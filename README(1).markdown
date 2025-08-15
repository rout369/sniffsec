# SniffSec - Network Scanner Tool

SniffSec is a Python-based network scanning and monitoring tool designed to capture, analyze, and visualize network traffic. It provides functionalities for packet sniffing, ARP and DNS spoofing detection, and real-time network activity monitoring with interactive visualizations.

## Features

- **Packet Sniffing**: Capture and display detailed packet information with human-readable explanations for protocols like DNS, ARP, TCP, UDP, and IP.
- **ARP Spoofing Detection**: Identify potential ARP spoofing attacks by monitoring duplicate ARP replies.
- **DNS Spoofing Detection**: Detect DNS spoofing by analyzing mismatched IP responses to DNS queries.
- **Network Activity Monitoring**: Monitor network traffic with performance optimizations, including sampling and live statistics display.
- **Interactive Visualizations**: Generate 3D-effect pie charts, 3D scatter plots, and bar charts for protocol and IP distribution using Plotly.

## Prerequisites

- **Python 3.6+**
- **Operating Systems**: Windows or Linux (for Wi-Fi signal strength detection)
- **Required Python Packages**:
  - `scapy`
  - `plotly`
  - `tqdm`
  - `rich`
- **System Requirements**:
  - Administrative/root privileges for packet sniffing (e.g., `sudo` on Linux).
  - A compatible network interface (e.g., `Wi-Fi`, `eth0`, `wlan0`).

Install dependencies using:
```bash
pip install scapy plotly tqdm rich
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/rout369/sniffsec.git
   cd sniffsec
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure you have administrative privileges to run the tool for packet capturing.

## Usage

Run the tool using the `sniffsec.py` script with the appropriate arguments. Below are some example commands:

### 1. Packet Sniffing
Capture and display packets on a specified interface:
```bash
python sniffsec.py --mode sniffer --interface Wi-Fi --packet-limit 100
```
- Filters packets interactively (e.g., `dns`, `arp`, `tcp`, `udp`, `ip`, `all`, or `quit`).

### 2. ARP Spoofing Detection
Monitor for ARP spoofing on a specified interface:
```bash
python sniffsec.py --mode spoofing --interface wlan0
```

### 3. DNS Spoofing Detection
Monitor for DNS spoofing on a specified interface:
```bash
python sniffsec.py --mode dns --interface eth0
```

### 4. Network Activity Monitoring
Monitor network activity and save results to a JSON file:
```bash
python sniffsec.py --mode monitor --interface Wi-Fi --output activity.json --packet-limit 300 --sample-rate 10
```
- Optionally generate interactive graphs (3D-effect pie chart and bar chart) after monitoring.

## Output

- **Sniffer Mode**: Displays real-time packet information with human-readable explanations.
- **Spoofing/DNS Detection**: Logs potential spoofing events to the console.
- **Monitor Mode**: Saves network activity (IP and protocol counters) to a JSON file and displays a live table with signal strength. Optionally generates an interactive HTML plot (`<output>_plot.html`).

## Project Structure

- `sniffsec.py`: Main script for running the tool with command-line arguments.
- `banner.py`: Displays the initial loading bar and logo.
- `signal.py`: Handles signal strength detection and live table updates.
- `detect.py`: Implements ARP and DNS spoofing detection.
- `monitor.py`: Manages network activity monitoring, packet sniffing, and data saving.
- `graph.py`: Generates interactive 3D-effect graphs from JSON data.

## Example Output

### Monitoring Mode
- Live table showing unique IPs, protocol counts, and signal strength.
- JSON output (`activity.json`):
  ```json
  {
      "ip_counter": {
          "192.168.1.1": 150,
          "192.168.1.2": 50
      },
      "protocol_counter": {
          "TCP": 100,
          "UDP": 50,
          "ARP": 20
      }
  }
  ```
- Interactive HTML plot with toggleable 2D pie chart, 3D scatter plot, and IP bar chart.

## Notes

- Ensure you have the correct network interface name (e.g., use `ifconfig` on Linux or `netsh wlan show interfaces` on Windows to find it).
- The tool requires administrative privileges to capture packets.
- Use `Ctrl+C` to stop sniffing or monitoring.
- Graphs require a compatible browser to view the interactive HTML output.

## Author

- **Creator**: Biswajit
- **GitHub**: [rout369](https://github.com/rout369)
- **Version**: 1.0

## License

This project is licensed under the **GNU General Public License v3.0**. See the [LICENSE](LICENSE) file for details.