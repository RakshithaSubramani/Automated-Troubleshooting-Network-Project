import scapy.all as scapy
import pandas as pd
import time
from collections import defaultdict

# Load pcap file
pcap_file = "network_logs.pcap"
packets = scapy.rdpcap(pcap_file)

# Data storage
data = []
ip_packet_count = defaultdict(int)
syn_count = defaultdict(int)
ack_count = defaultdict(int)
first_seen = {}
last_seen = {}

# Extract Features
for pkt in packets:
    if pkt.haslayer(scapy.IP):
        src_ip = pkt[scapy.IP].src
        dst_ip = pkt[scapy.IP].dst
        protocol = pkt[scapy.IP].proto
        packet_size = len(pkt)

        # Track packet count per IP
        ip_packet_count[src_ip] += 1

        # Track first and last seen time for connection duration
        timestamp = pkt.time
        if src_ip not in first_seen:
            first_seen[src_ip] = timestamp
        last_seen[src_ip] = timestamp

        # Count SYN and ACK packets for ratio calculation
        if pkt.haslayer(scapy.TCP):
            if pkt[scapy.TCP].flags == 'S':  # SYN flag
                syn_count[src_ip] += 1
            if pkt[scapy.TCP].flags == 'A':  # ACK flag
                ack_count[src_ip] += 1

        # Store extracted data
        data.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "packet_size": packet_size,
            "timestamp": timestamp
        })

# Calculate SYN to ACK Ratio
syn_ack_ratio = {}
for ip in syn_count:
    syn_ack_ratio[ip] = syn_count[ip] / (ack_count[ip] + 1)  # +1 to avoid division by zero

# Calculate Connection Durations
connection_durations = {ip: last_seen[ip] - first_seen[ip] for ip in first_seen}

# Convert to Pandas DataFrame
df = pd.DataFrame(data)

# Add additional computed features
df["packet_count"] = df["src_ip"].map(ip_packet_count)
df["connection_duration"] = df["src_ip"].map(connection_durations)
df["syn_ack_ratio"] = df["src_ip"].map(syn_ack_ratio)

# Save extracted features to CSV
df.to_csv("network_features.csv", index=False)

print("Feature extraction completed. Data saved to network_features.csv")
