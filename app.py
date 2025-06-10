from flask import Flask, render_template, jsonify, request, send_file
import threading
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import matplotlib.pyplot as plt
import os
import json
import numpy as np
from collections import defaultdict


app = Flask(__name__, static_folder='static')

# Global variables
is_scanning = False
scan_thread = None
packet_data = []
anomalies = []  # List to store anomaly packets (e.g., ICMP)
csv_filename = "network_traffic.csv"

# Your correct network interface for sniffing (from Get-NetAdapter) or getmac /v /fo list
INTERFACE = "\\Device\\NPF_{90FCB7D0-08BD-40EA-8D00-E2562F6EF91E}"

def get_protocol(packet):
    """Determine the protocol of the packet more specifically."""
    if IP in packet:
        if TCP in packet:
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            if dport == 80 or sport == 80:
                return "HTTP"
            elif dport == 443 or sport == 443:
                return "HTTPS"
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif ICMP in packet:
            return "ICMP"
    return "Other"

def packet_callback(packet):
    """Handles incoming packets and stores them."""
    global packet_data, anomalies
    if not is_scanning:
        return

    if IP in packet:
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        protocol = get_protocol(packet)
        size = len(packet)
        ttl = packet[IP].ttl  # Extract TTL
        
        # Calculate energy based on packet size and TTL
        # Using a more realistic formula: energy = size * (1/TTL) * 0.1
        energy = round((size * (1/ttl) * 0.1), 2)
        
        timestamp = datetime.now().strftime("%H:%M:%S")

        # Store the packet
        packet_data.append({
            "Timestamp": timestamp,
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol,
            "Size": size,
            "TTL": ttl,
            "Energy": energy
        })

        # Anomaly detection: Detecting ICMP packets as anomalies
        if protocol == "ICMP":
            anomalies.append({
                "Timestamp": timestamp,
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Protocol": protocol,
                "Size": size,
                "TTL": ttl,
                "Energy": energy
            })

        # Limit to last 500 packets to prevent memory issues
        if len(packet_data) > 500:
            packet_data.pop(0)

        print(f"Captured Packet: {src_ip} -> {dst_ip} | {protocol} | {size} bytes | TTL: {ttl} | Energy: {energy}")

        # Save to CSV periodically
        if len(packet_data) % 50 == 0:
            save_to_csv()

def save_to_csv():
    """Saves captured packet data to CSV."""
    if packet_data:
        df = pd.DataFrame(packet_data)
        df.to_csv(csv_filename, index=False)
        print("✅ Packet data saved to CSV!")

def start_sniffer():
    """Starts packet sniffing on the correct interface."""
    global is_scanning
    if not INTERFACE:
        print("❌ No valid network interface found!")
        return

    print(f"📡 Sniffing on interface: {INTERFACE}")

    def stop_sniffer(packet):
        return not is_scanning  # Stops sniffing when is_scanning = False

    sniff(prn=packet_callback, store=False, iface=INTERFACE, stop_filter=stop_sniffer)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/start', methods=['POST'])
def start_scan():
    """Starts network packet sniffing."""
    global is_scanning, scan_thread, packet_data
    if not is_scanning:
        is_scanning = True
        packet_data = []
        scan_thread = threading.Thread(target=start_sniffer, daemon=True)
        scan_thread.start()
        return jsonify({'status': 'success', 'message': 'Packet sniffing started'})
    return jsonify({'status': 'error', 'message': 'Sniffing is already running'})

@app.route('/api/stop', methods=['POST'])
def stop_scan():
    """Stops network packet sniffing."""
    global is_scanning
    if is_scanning:
        is_scanning = False  # Stop sniffing
        save_to_csv()
        return jsonify({'status': 'success', 'message': 'Packet sniffing stopped'})
    return jsonify({'status': 'error', 'message': 'No active sniffing session'})

@app.route('/api/csv_data')
def get_csv_data():
    """Returns captured packet data."""
    return jsonify({'data': packet_data})

@app.route('/api/anomalies')
def get_anomalies():
    """Returns anomaly packets (ICMP)."""
    return jsonify({'anomalies': anomalies})

@app.route('/api/visualize', methods=['GET'])
def visualize_data():
    """Creates visualizations based on the requested chart type."""
    chart_type = request.args.get('type', 'protocol')
    
    # Generate all chart types at once for the tabbed interface
    protocol_chart = make_visualization('protocol')
    size_chart = make_visualization('size')
    energy_chart = make_visualization('energy')
    
    if not protocol_chart and not size_chart and not energy_chart:
        return jsonify({'error': 'No data available for visualization'})
    
    return jsonify({
        'protocol_chart': protocol_chart,
        'size_chart': size_chart,
        'energy_chart': energy_chart
    })

def make_visualization(chart_type):
    """Creates various visualizations of packet data."""
    if not os.path.exists('static'):
        os.makedirs('static')
        
    df = pd.DataFrame(packet_data)
    if df.empty:
        return None
        
    plt.figure(figsize=(10, 6))
    
    if chart_type == 'protocol':
        # Protocol distribution pie chart
        protocol_counts = df['Protocol'].value_counts()
        plt.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', 
                shadow=True, startangle=90, colors=['#4361ee', '#3f37c9', '#f72585', '#4cc9f0', '#560bad'])
        plt.title('Protocol Distribution', fontsize=16)
        img_path = "static/protocol_chart.png"
        
    elif chart_type == 'size':
        # Packet size distribution histogram
        plt.hist(df['Size'], bins=20, color='#4361ee', alpha=0.7, edgecolor='black')
        plt.xlabel('Packet Size (bytes)', fontsize=12)
        plt.ylabel('Frequency', fontsize=12)
        plt.title('Packet Size Distribution', fontsize=16)
        plt.grid(True, alpha=0.3)
        img_path = "static/size_chart.png"
        
    elif chart_type == 'energy':
        # Energy consumption by protocol
        protocol_energy = df.groupby('Protocol')['Energy'].sum().sort_values(ascending=False)
        protocol_energy.plot(kind='bar', color=['#f72585', '#4361ee', '#4cc9f0', '#3f37c9', '#560bad'])
        plt.xlabel('Protocol', fontsize=12)
        plt.ylabel('Total Energy', fontsize=12)
        plt.title('Energy Consumption by Protocol', fontsize=16)
        plt.grid(axis='y', alpha=0.3)
        plt.xticks(rotation=0)
        img_path = "static/energy_chart.png"
    
    else:
        return None
    
    plt.tight_layout()
    plt.savefig(img_path, dpi=100, bbox_inches='tight')
    plt.close()
    
    return f"/{img_path}"

if __name__ == '__main__':
    # Create static folder if it doesn't exist
    if not os.path.exists('static'):
        os.makedirs('static')
    
    # Initialize empty CSV file
    if not os.path.isfile(csv_filename):
        save_to_csv()
        
    app.run(debug=True, host='0.0.0.0')