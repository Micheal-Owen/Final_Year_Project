import scapy.all as scapy
import joblib

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import signal
import sys
import requests

# Load the pre-trained model
model = joblib.load('mlp_model.joblib')

# Load the scaler
scaler = joblib.load('scaler.joblib')

# Load the label encoder
label_encoder = joblib.load('label_encoder.joblib')

# Django server URL``
DJANGO_SERVER_URL = 'http://127.0.0.1:8000/api/packet/'

# Function to extract features from packets
def extract_features(packet):
    """
    Extract features from a packet.

    Args:
        packet (scapy.packet.Packet): The packet to extract features from.

    Returns:
        dict: A dictionary containing the extracted features.
    """
    features = {}
    try:
        # Extract IP layer and transport layer information
        ip_layer = packet[scapy.IP]
        transport_layer = packet[scapy.TCP] if packet.haslayer(scapy.TCP) else packet[scapy.UDP]
        payload_len = len(ip_layer.payload)

        # Extract basic features
        features['Dst Port'] = transport_layer.dport
        features['Protocol'] = packet.proto
        features['Flow Duration'] = abs(packet.time - ip_layer.time)
        features['Tot Fwd Pkts'] = 1  # Each packet is one forward packet
        features['Tot Bwd Pkts'] = 0  # No backward packets in this context
        features['TotLen Fwd Pkts'] = payload_len
        features['TotLen Bwd Pkts'] = 0
        features['Fwd Pkt Len Max'] = payload_len
        features['Fwd Pkt Len Min'] = payload_len
        features['Fwd Pkt Len Mean'] = payload_len
        features['Fwd Pkt Len Std'] = 0
        features['Bwd Pkt Len Max'] = 0
        features['Bwd Pkt Len Min'] = 0
        features['Bwd Pkt Len Mean'] = 0
        features['Bwd Pkt Len Std'] = 0
        features['Flow Byts/s'] = payload_len / features['Flow Duration'] if features['Flow Duration'] > 0 else 0
        features['Flow Pkts/s'] = 1 / features['Flow Duration'] if features['Flow Duration'] > 0 else 0
        features['Flow IAT Mean'] = features['Flow Duration']
        features['Flow IAT Std'] = 0
        features['Flow IAT Max'] = features['Flow Duration']
        features['Flow IAT Min'] = features['Flow Duration']
        features['Fwd IAT Tot'] = features['Flow Duration']
        features['Fwd IAT Mean'] = features['Flow Duration']
        features['Fwd IAT Std'] = 0
        features['Fwd IAT Max'] = features['Flow Duration']
        features['Fwd IAT Min'] = features['Flow Duration']
        features['Bwd IAT Tot'] = 0
        features['Bwd IAT Mean'] = 0
        features['Bwd IAT Std'] = 0
        features['Bwd IAT Max'] = 0
        features['Bwd IAT Min'] = 0
        features['Fwd PSH Flags'] = 1 if packet.haslayer(scapy.TCP) and 'P' in packet[scapy.TCP].flags else 0
        features['Bwd PSH Flags'] = 0
        features['Fwd URG Flags'] = 1 if packet.haslayer(scapy.TCP) and 'U' in packet[scapy.TCP].flags else 0
        features['Bwd URG Flags'] = 0
        features['Fwd Header Len'] = len(ip_layer)
        features['Bwd Header Len'] = 0
        features['Fwd Pkts/s'] = 1 / features['Flow Duration'] if features['Flow Duration'] > 0 else 0
        features['Bwd Pkts/s'] = 0
        features['Pkt Len Min'] = payload_len
        features['Pkt Len Max'] = payload_len
        features['Pkt Len Mean'] = payload_len
        features['Pkt Len Std'] = 0
        features['Pkt Len Var'] = 0
        features['FIN Flag Cnt'] = 1 if packet.haslayer(scapy.TCP) and 'F' in packet[scapy.TCP].flags else 0
        features['SYN Flag Cnt'] = 1 if packet.haslayer(scapy.TCP) and 'S' in packet[scapy.TCP].flags else 0
        features['RST Flag Cnt'] = 1 if packet.haslayer(scapy.TCP) and 'R' in packet[scapy.TCP].flags else 0
        features['PSH Flag Cnt'] = 1 if packet.haslayer(scapy.TCP) and 'P' in packet[scapy.TCP].flags else 0
        features['ACK Flag Cnt'] = 1 if packet.haslayer(scapy.TCP) and 'A' in packet[scapy.TCP].flags else 0
        features['URG Flag Cnt'] = 1 if packet.haslayer(scapy.TCP) and 'U' in packet[scapy.TCP].flags else 0
        features['CWE Flag Count'] = 0  # Placeholder
        features['ECE Flag Cnt'] = 1 if packet.haslayer(scapy.TCP) and 'E' in packet[scapy.TCP].flags else 0
        features['Down/Up Ratio'] = 0  # Placeholder, needs context from multiple packets
        features['Pkt Size Avg'] = payload_len
        features['Fwd Seg Size Avg'] = payload_len
        features['Bwd Seg Size Avg'] = 0
        features['Fwd Byts/b Avg'] = payload_len
        features['Fwd Pkts/b Avg'] = 1 / payload_len if payload_len > 0 else 0
        features['Fwd Blk Rate Avg'] = 0  # Placeholder
        features['Bwd Byts/b Avg'] = 0
        features['Bwd Pkts/b Avg'] = 0
        features['Bwd Blk Rate Avg'] = 0  # Placeholder
        features['Subflow Fwd Pkts'] = 1  # Assuming one packet per subflow for simplicity
        features['Subflow Fwd Byts'] = payload_len
        features['Subflow Bwd Pkts'] = 0
        features['Subflow Bwd Byts'] = 0
        features['Init Fwd Win Byts'] = transport_layer.window if packet.haslayer(scapy.TCP) else 0
        features['Init Bwd Win Byts'] = 0
        features['Fwd Act Data Pkts'] = 1
        features['Fwd Seg Size Min'] = payload_len
        features['Active Mean'] = features['Flow Duration']
        features['Active Std'] = 0
        features['Active Max'] = features['Flow Duration']
        features['Active Min'] = features['Flow Duration']
        features['Idle Mean'] = 0
        features['Idle Std'] = 0
        features['Idle Max'] = 0
        features['Idle Min'] = 0
    except IndexError:
        pass
    return features

# Function to send packet data to the Django server
def send_packet_data(packet_data):
    """
    Sends packet data to the Django server.

    Args:
        packet_data (dict): Packet data to be sent.

    Returns:
        None
    """
    try:
        # Send POST request to Django server
        response = requests.post(DJANGO_SERVER_URL, json=packet_data)

        # Check response status code
        if response.status_code == 200:
            print("Packet data sent successfully")
        else:
            print(f"Failed to send packet data: {response.status_code}")
    except Exception as e:
        # Print error message if any exception occurs
        print(f"Error sending packet data: {e}")

# Graceful shutdown
def signal_handler(sig, frame):
    """
    Signal handler for handling SIGINT signal (Ctrl+C).

    Args:
        sig (int): The signal number.
        frame: The current stack frame.

    Returns:
        None
    """
    # Print message indicating that packet capture is stopping
    print("Stopping packet capture...")
    
    # Exit the program
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Main function to process packets
def main():
    """
    Main function to process packets and send packet data to Django server.

    This function sets up a packet sniff and processes each packet that is captured.
    It extracts features from each packet and uses a pre-trained model to predict
    whether the packet is an attack or not. It then sends the packet data to the
    Django server using the send_packet_data function.

    Returns:
        None
    """

    def process_packet(packet):
        """
        Process a captured packet and send the packet data to the Django server.

        Args:
            packet (scapy.packet.Packet): The captured packet.

        Returns:
            None
        """
        features = extract_features(packet)
        if features:
            features_df = pd.DataFrame([features])
            features_scaled = scaler.transform(features_df)
            prediction = model.predict(features_scaled)
            predicted_label = label_encoder.inverse_transform(prediction)[0]

            # Get transport layer information
            transport_layer = packet[scapy.TCP] if packet.haslayer(scapy.TCP) else packet[scapy.UDP]
            packet_data = {
                'src_ip': packet[scapy.IP].src,
                'dst_ip': packet[scapy.IP].dst,
                'dst_port': transport_layer.dport,
                'protocol': packet.proto,
                'length': len(packet),
                'is_attack': predicted_label != 'Benign',
                'attack_type': predicted_label,
                'timestamp': datetime.now().isoformat()
            }
            
            send_packet_data(packet_data)
            print(f"Source IP: {packet[scapy.IP].src}, Destination IP: {packet[scapy.IP].dst}, Prediction: {predicted_label}")

    print("Starting packet capture. Press Ctrl+C to stop.")
    scapy.sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
