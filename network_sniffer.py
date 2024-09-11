import time
from scapy.all import sniff, wrpcap

packet_count = 0
max_packets = 100
packets = []

def packet_sniffer(packet):
    global packet_count
    global packets

    print(packet.summary())
    packets.append(packet)
    packet_count += 1

    if packet_count >= max_packets:
        stop_sniffer()

def stop_sniffer():
    print("\nStopping packet capture...")
    raise KeyboardInterrupt

def main():
    global packets
    print("Capturing packets started:")

    timeout = 10

    try:
        sniff(prn=packet_sniffer, timeout=timeout)
    except KeyboardInterrupt:
        pass
    finally:
        if packets:
            wrpcap('captured_packets.pcap', packets)
            print(f"Capturing packets complete. {len(packets)} packets were saved to 'captured_packets.pcap'.")
        else:
            print("There are no packets captured.")

if __name__ == "__main__":
    main()
