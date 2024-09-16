import sys
from scapy.all import rdpcap, TCP, UDP, ICMP, IP, raw
import time

def parse_rules_file(file_path):
    rules = []
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith("#") or not line.strip():
                continue
            rule = line.strip().rstrip(');')  # Remove ');'
            rules.append(rule)
            # print(f"Parsed rule: {rule}")  # Debugging
    return rules

def match_flags(flags, packet_flags):
    # the below flags and corresponding values were found from https://www.noction.com/blog/tcp-flags
    fin = 0b00000001
    syn = 0b00000010
    rst = 0b00000100
    ack = 0b00010000

    flag = flags[0] # ignore any trailing +

    # for flag in flags: # loop through flags required by rule
    if flag == 'F': # fin flag required
        if not (fin & packet_flags): # if that flag is not set in the packet
            return False
    elif flag == 'A': 
        if not (ack & packet_flags): # if that flag is not set in the packet
            return False
    elif flag == 'S': 
        if not (syn & packet_flags): # if that flag is not set in the packet
            return False
    elif flag == 'R': 
        if not (rst & packet_flags): # if that flag is not set in the packet
            return False
    return True

def check_tcp_flooding(packet, rule):
    return True

def match_packet(packet, rule):
    src_ip, src_port, dst_ip, dst_port, content, flags = parse_rule(rule)

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
        
        # if src_port != 'any' and packet[TCP].sport != int(src_port):
        #     return False
        # elif dst_port != 'any' and packet[TCP].dport != int(dst_port):
        #     return False
        # elif content is not None and raw in packet: # if there is a payload, decode it and check it
        #     payload = packet[raw].load.decode(errors='ignore')
        #     if content not in payload:
        #         return False
        if not check_port_and_content(packet, TCP, src_port, dst_port, content):
            return False
        elif len(flags) > 0: # If there are flags present in the rules          
            packet_flags = packet[TCP].flags # Get flags in packet
            if not match_flags(flags, packet_flags): # ensure all required flags are present
                return False
        elif not check_tcp_flooding(): # Check TCP flooding
            return False

        return True
    # elif 'icmp' in rule:
    if ICMP in packet and ('icmp' in rule or 'ip' in rule):
        if ICMP not in packet or IP not in packet or TCP in packet or UDP in packet:  # Ensure packet contains both ICMP and IP
            return False
        
        if not check_port_and_content(packet, ICMP, src_port, dst_port, content):
            return False
        # if src_port != 'any' and packet[ICMP].sport != int(src_port):
        #     return False
        # elif dst_port != 'any' and packet[ICMP].dport != int(dst_port):
        #     return False
        # elif content is not None and raw in packet: # if there is a payload, decode it and check it
        #     payload = packet[raw].load.decode(errors='ignore')
        #     if content not in payload:
        #         return False  
        # return True
    # elif 'udp' in rule: 
    if UDP in packet and ('udp' in rule or 'ip' in rule):
        if UDP not in packet or IP not in packet or TCP in packet or ICMP in packet: 
            return False

        if not check_port_and_content(packet, UDP, src_port, dst_port, content):
            return False
        # if src_port != 'any' and packet[UDP].sport != int(src_port):
        #     return False
        # elif dst_port != 'any' and packet[UDP].dport != int(dst_port):
        #     return False
        # elif content is not None and raw in packet: # if there is a payload, decode it and check it
        #     payload = packet[raw].load.decode(errors='ignore')
        #     if content not in payload:
        #         return False
        # return True
    return False

def check_port_and_content(packet, protocol, src_port, dst_port, content):
    if src_port != 'any' and packet[UDP].sport != int(src_port):
        return False
    elif dst_port != 'any' and packet[UDP].dport != int(dst_port):
        return False
    elif content is not None and raw in packet: # if there is a payload, decode it and check it
        payload = packet[raw].load.decode(errors='ignore')
        if content not in payload:
            return False
    return True

# Parse source and destination IPs and Ports + content if present
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

    content = None
    if 'content' in rule:
        content_start = rule.find('content:') + len('content:')
        if rule[content_start] == ' ': # if space present after ':'
            content_start += 1 # increment start to ignore space
        content_start = rule.find('"', content_start) + 1
        content_end = rule.find('"', content_start) 
        content = rule[content_start:content_end] # store content

    # Parse flags
    flags = []
    if 'flags' in rule:
        flag_start = rule.find('flags:') + len('flags:')
        if rule[flag_start] == ' ':  # if space present after ':'
            flag_start += 1
        flag_end = rule.find(';', flag_start)
        if flag_end == -1: # if ';' not found since end of rule set end of flags to end of rule
            flag_end = len(rule)
        flags_stripped= rule[flag_start:flag_end].strip() # separate the flags - assuming no +/- will be present
        flags.append(flags_stripped)

    # print(f"packet {src_ip} {src_port} {dst_ip} {dst_port}") - debugging
    return src_ip, src_port, dst_ip, dst_port, content, flags

def log_alert(message, file):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    file.write(f"{timestamp} - Alert: {message}\n")

def main():
    if len(sys.argv) != 3:
        print("Usage: python IDS.py <path_to_pcap_file> <path_to_IDS_rules>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    rules_file = sys.argv[2]

    rules = parse_rules_file(rules_file)
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