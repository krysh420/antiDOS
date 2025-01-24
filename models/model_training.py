import glob
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
import numpy as np
import joblib  # For saving and loading the model
from scapy.all import rdpcap
import os

def load_all_datasets():
    """Load and combine all CSV files from data/processed directory"""
    all_files = glob.glob("./data/processed/*.csv")
    combined_data = pd.concat([pd.read_csv(f) for f in all_files], ignore_index=True)
    return combined_data.drop_duplicates()

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

# Load the data
data = load_all_datasets()

# Define features and target
X = data[["src_ip", "dst_ip", "protocol", "length", "src_port", "dst_port"]].copy() 
y = data["label"]

# Handle "0.0.0.0" IP addresses
X.loc[:, "src_ip"] = X["src_ip"].replace("0.0.0.0", "unknown_ip")
X.loc[:, "dst_ip"] = X["dst_ip"].replace("0.0.0.0", "unknown_ip")

# Encode categorical features (using One-Hot Encoding for IP addresses)
ohe_src_ip = OneHotEncoder(handle_unknown='ignore') 
ohe_dst_ip = OneHotEncoder(handle_unknown='ignore') 

protocol_values = np.append(data["protocol"].unique(), "unknown") 

# Create and fit the LabelEncoder
ohe_protocol = LabelEncoder()
ohe_protocol.fit(protocol_values)

# Fit and transform the IP addresses
X_src_ip_encoded = ohe_src_ip.fit_transform(X["src_ip"].values.reshape(-1, 1)).toarray() 
X_dst_ip_encoded = ohe_dst_ip.fit_transform(X["dst_ip"].values.reshape(-1, 1)).toarray()
X_protocol_encoded = ohe_protocol.transform(X["protocol"]).reshape(-1, 1) 

# Concatenate all features into a single array
X_encoded = np.concatenate((X_src_ip_encoded, 
                           X_dst_ip_encoded, 
                           X_protocol_encoded, 
                           X["length"].values.reshape(-1, 1), 
                           X["src_port"].values.reshape(-1, 1), 
                           X["dst_port"].values.reshape(-1, 1)), 
                          axis=1)

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_encoded, y, test_size=0.2, random_state=42)

# Create and train the KNN model
knn = KNeighborsClassifier(n_neighbors=5) 
knn.fit(X_train, y_train)

# Save the trained model
model_filename = "./models/knn_model.joblib"  # Choose a suitable filename
joblib.dump(knn, model_filename)
print(f"Trained model saved to: {model_filename}")

# Make predictions on the testing set (optional)
y_pred = knn.predict(X_test)

# Evaluate accuracy on the testing set (optional)
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy) 

# **Using the Model for New Data Prediction**

# Load the saved model
loaded_model = joblib.load(model_filename)

# Load and preprocess the new data
new_data_dir = "./data/raw/new_data" 
new_data_features = []

for filename in os.listdir(new_data_dir):
    filepath = os.path.join(new_data_dir, filename) 
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"Error reading file: {filepath} - {e}")
        continue  # Skip files that cannot be read by rdpcap

    for packet in packets:
        features = extract_features(packet)
        if features:
            new_data_features.append(features)

if not new_data_features:
    print("No valid packets found in the specified directory.")
    exit()

new_data_df = pd.DataFrame(new_data_features)

# Handle "0.0.0.0" IP addresses
new_data_df.loc[:, "src_ip"] = new_data_df["src_ip"].replace("0.0.0.0", "unknown_ip")
new_data_df.loc[:, "dst_ip"] = new_data_df["dst_ip"].replace("0.0.0.0", "unknown_ip")

# Handle unseen protocols
new_data_df["protocol"] = new_data_df["protocol"].replace(
    list(set(new_data_df["protocol"].unique()) - set(ohe_protocol.classes_)), "unknown"
) 

# Encode categorical features (using the same encoders as before)
new_data_src_ip_encoded = ohe_src_ip.transform(new_data_df["src_ip"].values.reshape(-1, 1)).toarray() 
new_data_dst_ip_encoded = ohe_dst_ip.transform(new_data_df["dst_ip"].values.reshape(-1, 1)).toarray()
new_data_protocol_encoded = ohe_protocol.transform(new_data_df["protocol"]).reshape(-1, 1) 



# Concatenate all features into a single array
new_data_encoded = np.concatenate((new_data_src_ip_encoded, 
                                  new_data_dst_ip_encoded, 
                                  new_data_protocol_encoded, 
                                  new_data_df["length"].values.reshape(-1, 1), 
                                  new_data_df["src_port"].values.reshape(-1, 1), 
                                  new_data_df["dst_port"].values.reshape(-1, 1)), 
                                 axis=1)

# Make predictions
predictions = loaded_model.predict(new_data_encoded) 
joblib.dump(ohe_src_ip, 'models/encoders/ohe_src_ip.joblib')
joblib.dump(ohe_dst_ip, 'models/encoders/ohe_dst_ip.joblib')
joblib.dump(ohe_protocol, 'models/encoders/ohe_protocol.joblib')
print("Encoders saved successfully!")
print("Predictions:", predictions)