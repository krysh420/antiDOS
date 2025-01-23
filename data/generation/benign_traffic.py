import os
import time
from multiprocessing import Process

def simulate_ping(target_ip, interval=1):
    """
    Simulates ICMP ping requests.
    Parameters:
    - target_ip: IP to ping.
    - interval: Interval between pings in seconds.
    """
    print(f"Starting ping simulation to {target_ip}...")
    while True:
        os.system(f"ping -c 1 {target_ip} > /dev/null 2>&1")
        time.sleep(interval)

def simulate_http_requests(target_url, interval=2):
    """
    Simulates benign HTTP requests using curl.
    Parameters:
    - target_url: URL to send requests to.
    - interval: Interval between requests in seconds.
    """
    print(f"Starting HTTP request simulation to {target_url}...")
    while True:
        os.system(f"curl -s {target_url} > /dev/null 2>&1")
        time.sleep(interval)

def generate_benign_traffic(target_ip, target_url, duration=60):
    """
    Generate benign traffic for a specific duration.
    Parameters:
    - target_ip: Target IP for ping.
    - target_url: Target URL for HTTP requests.
    - duration: Duration to generate traffic in seconds.
    """
    print(f"Generating benign traffic for {duration} seconds...")
    processes = [
        Process(target=simulate_ping, args=(target_ip,)),
        Process(target=simulate_http_requests, args=(target_url,))
    ]

    for process in processes:
        process.start()

    time.sleep(duration)

    for process in processes:
        process.terminate()

    print("Benign traffic generation completed.")

if __name__ == "__main__":
    TARGET_IP = "192.168.123.129"  # Replace with your target IP
    TARGET_URL = "http://192.168.123.129"  # Replace with your target URL
    DURATION = 60  # Traffic generation duration in seconds

    generate_benign_traffic(TARGET_IP, TARGET_URL, DURATION)
