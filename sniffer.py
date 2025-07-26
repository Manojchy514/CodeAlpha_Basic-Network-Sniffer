# Import the necessary modules from Scapy
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP

# For coloring the output
import sys
IS_WINDOWS = sys.platform.startswith('win')
if IS_WINDOWS:
    # Windows deserves coloring too :D
    from colorama import init
    init()

# Define color constants for output
R = '\033[91m'  # Red for protocols
G = '\033[92m'  # Green for source
Y = '\033[93m'  # Yellow for destination
B = '\033[94m'  # Blue for packet info
C = '\033[96m'  # Cyan for payload
E = '\033[0m'   # End color

def packet_callback(packet):
    """
    This function is called for each captured packet.
    It analyzes and prints key information about the packet.
    """
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"\n{B}[+] New Packet Captured{E}")
        print(f"{G}    Source IP: {ip_src}{E}")
        print(f"{Y}    Destination IP: {ip_dst}{E}")

        # Determine the protocol
        if TCP in packet:
            proto_name = "TCP"
            print(f"{R}    Protocol: {proto_name}{E}")
            print(f"    Src Port: {packet[TCP].sport}")
            print(f"    Dst Port: {packet[TCP].dport}")
            
            # Check for payload data
            if Raw in packet:
                payload = packet[Raw].load
                print(f"{C}    Payload:{E}")
                # Try to decode as UTF-8, else print raw bytes
                try:
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print(decoded_payload)
                except Exception:
                    print(payload)

        elif UDP in packet:
            proto_name = "UDP"
            print(f"{R}    Protocol: {proto_name}{E}")
            print(f"    Src Port: {packet[UDP].sport}")
            print(f"    Dst Port: {packet[UDP].dport}")
            if Raw in packet:
                payload = packet[Raw].load
                print(f"{C}    Payload:{E}")
                print(payload)

        elif ICMP in packet:
            proto_name = "ICMP"
            print(f"{R}    Protocol: {proto_name}{E}")
            # ICMP doesn't have ports, but has type and code
            print(f"    Type: {packet[ICMP].type}")
            print(f"    Code: {packet[ICMP].code}")
        
        else:
            # For other IP protocols (less common)
            print(f"{R}    Protocol Number: {proto}{E}")

def main():
    """
    Main function to start the sniffer.
    """
    print("Starting network sniffer...")
    # sniff() is the main capturing function of Scapy
    sniff(prn=packet_callback, store=0, count=20)
    # prn: function to call for each packet
    # store: 0 means we don't store any packets in memory
    # count: number of packets to capture. 0 means capture indefinitely until Ctrl+C
    print("\nSniffing complete.")

if __name__ == "__main__":
    main()