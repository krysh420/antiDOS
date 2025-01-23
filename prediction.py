import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
import numpy as np
import joblib  # For saving and loading the model
from scapy.all import sniff, IP, TCP, UDP 

# Load the trained model and encoders
loaded_model = joblib.load("./models/knn_model.joblib")
ohe_src_ip = joblib.load('./models/encoders/ohe_src_ip.joblib')  # Load pre-fitted encoders
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
            print(f"Prediction: {prediction[0]}")

            # Implement actions based on prediction 
            if prediction[0] == "ddos":
                print("DDoS attack detected!")
                # Take necessary actions (e.g., block traffic, send alert) 
        except ValueError as e:
            print(f"Prediction Error: {e}")
            print("Features_encoded shape:", features_encoded.shape) 
            print("Model expected features:", loaded_model.n_features_in_) 

def sniff_and_predict():
    sniff(prn=process_packet, store=0) 

if __name__ == "__main__":
    sniff_and_predict()