# antiDOS: A Machine Learning-Based DDoS Detection and Mitigation System

antiDOS is a robust project aimed at detecting and mitigating Distributed Denial-of-Service (DDoS) attacks in real-time. The project leverages machine learning, custom dataset generation, and real-time network packet analysis to ensure network resilience against malicious traffic. This repository contains the complete implementation, including dataset handling, model training, and live attack mitigation.

---

## Features

- **Real-Time Packet Analysis**: Monitors network traffic to detect anomalies.
- **Custom Dataset Generation**: Creates tailored datasets with benign and DDoS traffic.
- **Add your own Dataset**: Drop your dataset (in pcap file) in data/raw/(ddos or benign) or (in csv) data/processed.
- **Machine Learning Detection**: Utilizes the K-Nearest Neighbors (KNN) algorithm for accurate detection.
- **Dynamic IP Blacklisting**: Blocks malicious IP addresses upon detection.
- **SQL-Based IP Management**: Efficient handling of blocked and whitelisted IPs using SQLite.
- **Scalable Framework**: Designed for deployment in high-traffic environments.

---

## Getting Started

### Prerequisites

- Python 3.8+
- Virtual environment (optional but recommended)
- Root privileges for IP blocking (required by `iptables` or `ufw`)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/krysh420/antiDOS.git
   cd antiDOS
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv env
   source env/bin/activate  # Linux/Mac
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up the database:
   ```bash
   python db/setup_db.py
   ```

5. Train the model (optional if pre-trained model exists):
   ```bash
   python models/model_training.py
   ```

---

## Usage

### Real-Time DDoS Detection

Start the packet sniffer and detection system:
```bash
sudo python prediction.py
```

The system will:
- Monitor incoming network packets.
- Extract relevant features.
- Predict whether traffic is benign or a DDoS attack.
- Block malicious IPs dynamically using `iptables`.

### IP Management

Manage blacklisted and whitelisted IPs via the database interface:
```bash
python db/manage_db.py
```

Options include:
- Adding or removing IPs from the blacklist/whitelist.
- Displaying current entries in the database.

---

## Project Structure

```
.
├── data
│   ├── raw              # Raw traffic data (PCAP files)
│   ├── processed        # Processed datasets
│   └── features_extraction.py
├── db
│   ├── setup_db.py      # Database setup script
│   └── manage_db.py     # IP management script
├── models
│   ├── knn_model.joblib # Pre-trained KNN model
│   ├── encoders         # OneHotEncoder objects
│   └── model_training.py
├── prediction.py        # Real-time DDoS detection script
├── requirements.txt     # Dependencies
└── README.md            # Project documentation
```

---

## References

This project is based on the research paper:
- "[Distributed Denial-of-Service (DDoS) Attacks and Defense Mechanisms in Various Web-Enabled Computing Platforms](https://www.researchgate.net/publication/363114413_Distributed_Denial-of-Service_DDoS_Attacks_and_Defense_Mechanisms_in_Various_Web-Enabled_Computing_Platforms)"

---

## Contact

For questions or feedback, please reach out to [Krish Mishra](https://www.linkedin.com/in/krish-mishra-a9410917b/).

