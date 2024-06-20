import scapy.all as scapy
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import signal
import sys

# Load the pre-trained model
model = joblib.load('mlp_model.joblib')

# Load the scaler
scaler = joblib.load('scaler.joblib')

# Load the label encoder
label_encoder = joblib.load('label_encoder.joblib')

# Function to extract features from packets
def extract_features(packet):
    features = {}
    try:
        ip_layer = packet[scapy.IP]
        transport_layer = packet[scapy.TCP] if packet.haslayer(scapy.TCP) else packet[scapy.UDP]
        payload_len = len(ip_layer.payload)

        # Basic features
        features['Dst Port'] = transport_layer.dport
        features['Protocol'] = packet.proto
        features['Flow Duration'] = packet.time - ip_layer.time
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

# Graceful shutdown
def signal_handler(sig, frame):
    print("Stopping packet capture...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Main function to process packets
def main():
    def process_packet(packet):
        features = extract_features(packet)
        if features:
            features_df = pd.DataFrame([features])
            features_scaled = scaler.transform(features_df)
            prediction = model.predict(features_scaled)
            predicted_label = label_encoder.inverse_transform(prediction)
            transport_layer = packet[scapy.TCP] if packet.haslayer(scapy.TCP) else packet[scapy.UDP]
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            dst_port = transport_layer.dport
            print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Dst_Port: {dst_port}, Prediction: {predicted_label[0]}")

    print("Starting packet capture. Press Ctrl+C to stop.")
    scapy.sniff(prn=process_packet)

if __name__ == "__main__":
    main()
