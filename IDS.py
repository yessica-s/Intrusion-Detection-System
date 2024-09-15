import sys
from scapy.all import rdpcap, TCP, UDP, ICMP, IP
import time

def parse_rules(file_path):
    rules = []
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith("#") or not line.strip():
                continue
            rule = line.strip().rstrip(');')  # Remove ');'
            rules.append(rule)
            # print(f"Parsed rule: {rule}")  # Debugging
    return rules

def match_packet(packet, rule):
    src_ip, src_port, dst_ip, dst_port = parse_rule(rule)

    if IP not in packet:
        return False
    # check general IP addresses
    if src_ip != 'any' and packet[IP].src != src_ip:
            return False
    if dst_ip != 'any' and packet[IP].dst != dst_ip:
            return False

    # if 'tcp' in rule: # check TCP packets
    if TCP in packet and ('tcp' in rule or 'ip' in rule):
        if TCP not in packet or IP not in packet or ICMP in packet or UDP in packet:  # Ensure packet contains both TCP and IP
            return False
        
        if src_port != 'any' and packet[TCP].sport != int(src_port):
            return False
        
        if dst_port != 'any' and packet[TCP].dport != int(dst_port):
            return False
        return True
    # elif 'icmp' in rule:
    if ICMP in packet and ('icmp' in rule or 'ip' in rule):
        if ICMP not in packet or IP not in packet or TCP in packet or UDP in packet:  # Ensure packet contains both ICMP and IP
            return False

        if src_port != 'any' and packet[ICMP].sport != int(src_port):
            return False

        if dst_port != 'any' and packet[ICMP].dport != int(dst_port):
            return False
        return True
    # elif 'udp' in rule: 
    if UDP in packet and ('udp' in rule or 'ip' in rule):
        if UDP not in packet or IP not in packet or TCP in packet or ICMP in packet: 
            return False

        if src_port != 'any' and packet[UDP].sport != int(src_port):
            return False

        if dst_port != 'any' and packet[UDP].dport != int(dst_port):
            return False
        return True

    return False

# Parse source and destination IPs and Ports
def parse_rule(rule):
    rule = rule.rstrip(');')
    
    # Split the rule on spaces
    parts = rule.split()

    # Extract protocol, source IP, source port, destination IP, and destination port
    protocol = parts[1]
    src_ip = parts[2]
    src_port = parts[3]
    dst_ip = parts[5]
    dst_port = parts[6]

    # print(f"packet {src_ip} {src_port} {dst_ip} {dst_port}") - debugging
    return src_ip, src_port, dst_ip, dst_port

def log_alert(message, file):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    file.write(f"{timestamp} - Alert: {message}\n")
    # print(f"Logged alert: {message}")  # Debugging

def main():
    if len(sys.argv) != 3:
        print("Usage: python IDS.py <path_to_pcap_file> <path_to_IDS_rules>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    rules_file = sys.argv[2]

    rules = parse_rules(rules_file)
    packets = rdpcap(pcap_file)

    # Open the log file in write mode initially to clear its content
    with open('IDS_log.txt', 'w') as file:
        for packet in packets:
            for rule in rules:
                if match_packet(packet, rule):
                    msg_match = rule.find('msg:') # find where message starts
                    if msg_match != -1:
                        msg_start = rule.find('"', msg_match) + 1 # remove quotation marks
                        msg_end = rule.find('"', msg_start)
                        message = rule[msg_start:msg_end]
                        log_alert(message, file) # add message string to log file

if __name__ == "__main__":
    main()
