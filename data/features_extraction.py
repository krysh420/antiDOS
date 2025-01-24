# IMPORT JUST WHAT YOU NEED
from scapy.all import rdpcap 
import pandas as pd
import os

def extract_features(packet):
    """
    Extracts features from a single packet.

    Parameters:
        packet: Scapy packet object.

    Returns:
        Dictionary containing extracted features.
    """
    try:
        features = {
            "src_ip": packet[0][1].src if packet.haslayer("IP") else "0.0.0.0", 
            "dst_ip": packet[0][1].dst if packet.haslayer("IP") else "0.0.0.0",
            "protocol": packet[0].proto if packet.haslayer("IP") else 0, 
            "length": len(packet),
            "src_port": packet.sport if packet.haslayer("TCP") or packet.haslayer("UDP") else 0, 
            "dst_port": packet.dport if packet.haslayer("TCP") or packet.haslayer("UDP") else 0,
        }
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def process_pcap(input_dir, label, feature_list):
    """
    Processes all .pcap files in a directory, extracts features, and appends to a list.

    Parameters:
        input_dir: Directory containing .pcap files.
        label: Label for the traffic (e.g., 'benign' or 'ddos').
        feature_list: List to append extracted features.
    """
    print(f"Processing PCAP files in {input_dir}...")

    for filename in os.listdir(input_dir):
        filepath = os.path.join(input_dir, filename)
        print(f"Processing file: {filepath}")
        packets = rdpcap(filepath)

        for packet in packets:
            features = extract_features(packet)
            if features:
                features["label"] = label
                feature_list.append(features)

if __name__ == "__main__":
    benign_input_dir = "data/raw/benign"
    ddos_input_dir = "data/raw/ddos"
    output_file = "data/processed/labeled_features.csv"

    # Lists to store features for each label
    benign_features = []
    ddos_features = []

    # Process benign traffic
    process_pcap(benign_input_dir, "Normal", benign_features)

    # Process DDoS traffic
    process_pcap(ddos_input_dir, "DDOS", ddos_features)

    # Combine features into a single DataFrame
    all_features = benign_features + ddos_features
    df = pd.DataFrame(all_features)

    # Save features to a single CSV file
    df.to_csv(output_file, index=False)
    print(f"Feature extraction completed. Data saved to {output_file}.")