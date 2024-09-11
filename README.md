Features
Captures live network traffic.
Displays a real-time summary of captured packets.
Saves captured packets in `.pcap` format for detailed analysis.
Supports various network protocols including TCP, UDP, ARP, and more.

Prerequisites
Ensure that you have the following software installed on your machine:
Python 3.x: You can download it from [here](https://www.python.org/downloads/).

Scapy library: Install using `pip`:
  
  pip install scapy

Wireshark (optional): To analyze `.pcap` files, download Wireshark from [here](https://www.wireshark.org/download.html).

Installation
1. Clone the repository:
   
   git clone https://github.com/your-username/network-sniffer.git
   cd network-sniffer
   

2. Install the necessary dependencies:
   
   pip install -r requirements.txt

Usage
1. To start capturing packets, run the following command:
   
   python network_sniffer.py
   
2. The program will capture packets for 10 seconds (by default) and save them in a `captured_packets.pcap` file.

3. Open the `.pcap` file in Wireshark to analyze the packets in more detail.

Code Breakdown
`packet_sniffer(packet)`: Captures and prints a summary of each packet.
`stop_sniffer()`: Safely stops the packet capture.
`main()`: Initiates the packet sniffing and saves the captured packets to a `.pcap` file.

Example Output

Ether / IP / TCP 192.168.1.1:50238 > 52.182.143.210:https PA / Raw
Ether / ARP who has 192.168.1.105 says 192.168.1.1
