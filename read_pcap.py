from scapy.all import rdpcap
from datetime import datetime

def print_packets_with_time(pcap_file):
    packets = rdpcap(pcap_file)
    for packet in packets:
        timestamp = packet.time
        datetime_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        summary = packet.summary()
        print(f"{datetime_str}: {summary}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python read_pcap.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    print_packets_with_time(pcap_file)
