# IMPORT JUST WHAT YOU NEED
import sqlite3
import pandas as pd
import numpy as np
import joblib  # For saving and loading the model
from datetime import datetime
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from scapy.all import sniff, IP, TCP, UDP 
from time import time
import logging
from subprocess import run, PIPE
from collections import defaultdict


db = './db/blocked_ip.db'
con = sqlite3.connect(db)
cur = con.cursor()

blocked_ips = list(cur.execute("SELECT ip from blacklist"))
whitelisted_ips = cur.execute("SELECT ip from whitelist")
BLOCK_COOLDOWN = 10
last_block_time = defaultdict(int)
blocked_ips = set()

def add_ip(ip, table):
    current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Convert to string
    cur.execute(f"""
    INSERT INTO {table} (ip, date_added)
    SELECT ?, ?
    WHERE NOT EXISTS (
        SELECT 1 FROM {table} WHERE ip = ?
    )
""", (ip, current_date_time, ip))
    con.commit()

# Load the trained model and encoders
loaded_model = joblib.load("./models/knn_model.joblib")
ohe_src_ip = joblib.load('./models/encoders/ohe_src_ip.joblib') # Load pre-fitted encoders
ohe_dst_ip = joblib.load('./models/encoders/ohe_dst_ip.joblib')
ohe_protocol = joblib.load('./models/encoders/ohe_protocol.joblib') 

def extract_features(packet):
    """
    Extracts features from a single packet.

    Parameters:
        packet: Scapy packet object.

    Returns:
        Dictionary containing extracted features.
    """
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
        else:
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            protocol = 0

        length = len(packet)

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = 0
            dst_port = 0

        features = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "length": length,
            "src_port": src_port,
            "dst_port": dst_port,
        }
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def process_packet(packet):
    features = extract_features(packet)
    if features:
        # Create a DataFrame for encoding
        df = pd.DataFrame([features]) 

        # Handle "0.0.0.0" IP addresses
        df.loc[:, "src_ip"] = df["src_ip"].replace("0.0.0.0", "unknown_ip")
        df.loc[:, "dst_ip"] = df["dst_ip"].replace("0.0.0.0", "unknown_ip")

        # Encode categorical features using pre-fitted encoders
        src_ip_encoded = ohe_src_ip.transform(df["src_ip"].values.reshape(-1, 1)).toarray()
        dst_ip_encoded = ohe_dst_ip.transform(df["dst_ip"].values.reshape(-1, 1)).toarray()
        protocol_encoded = ohe_protocol.transform(df["protocol"]).reshape(-1, 1)

        # Concatenate all features into a single array (match the order from training)
        features_encoded = np.concatenate((
            src_ip_encoded, 
            dst_ip_encoded, 
            protocol_encoded, 
            df["length"].values.reshape(-1, 1), 
            df["src_port"].values.reshape(-1, 1), 
            df["dst_port"].values.reshape(-1, 1)
        ), axis=1)

        # Make prediction
        try:
            prediction = loaded_model.predict(features_encoded)
            src_ip = features['src_ip'].strip()  # Clean IP string once

            # Debug log for whitelist check
            logging.debug(f"Checking IP: {src_ip}")
            logging.debug(f"Whitelist contains: {whitelisted_ips}")

            if prediction[0] == "DDOS":
                if src_ip in whitelisted_ips:
                    logging.info(f"Skipping whitelisted IP: {src_ip}")
                    return
                
                current_time = time()
                
                # Check if IP was recently blocked
                if (src_ip not in blocked_ips and 
                    current_time - last_block_time.get(src_ip, 0) > BLOCK_COOLDOWN):
                    
                    # Update tracking
                    blocked_ips.add(src_ip)
                    last_block_time[src_ip] = current_time
                    
                    # Log the block
                    logging.warning(f"DDoS attack detected from: {src_ip}")
                    
                    # Add to database
                    add_ip(src_ip, 'blacklist')
                    
                    # Block using iptables
                    inc = f"sudo iptables -A INPUT -s {src_ip} -j DROP"
                    out = f"sudo iptables -A OUTPUT -s {src_ip} -j DROP"
                    result = run(inc.split(), stdout=PIPE, stderr=PIPE)
                    
                    if result.returncode == 0:
                        logging.info(f"Successfully blocked IP: {features['src_ip']}")
                    else:
                        logging.error(f"Failed to block IP: {features['src_ip']}")
                 
                    result = run(out.split(), stdout=PIPE, stderr=PIPE)
                    
                    if result.returncode == 0:
                        logging.info(f"Successfully blocked IP: {features['src_ip']}")
                    else:
                        logging.error(f"Failed to block IP: {features['src_ip']}")
                 
        except ValueError as e:
            print(f"Prediction Error: {e}")
            print("Features_encoded shape:", features_encoded.shape) 
            print("Model expected features:", loaded_model.n_features_in_) 

def sniff_and_predict():
    sniff(prn=process_packet, store=0) 

if __name__ == "__main__":
    sniff_and_predict()