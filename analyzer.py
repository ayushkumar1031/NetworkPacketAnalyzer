# analyzer.py
# Simple Network Packet Analyzer
# Author: Ayush Kumar
# Captures TCP, UDP, ICMP packets and logs them

from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(pkt):
    """
    Process each packet: extract source, destination, protocol and log it
    """
    if IP in pkt:
        ip_layer = pkt[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ""
        if TCP in pkt:
            proto = "TCP"
        elif UDP in pkt:
            proto = "UDP"
        elif ICMP in pkt:
            proto = "ICMP"
        log_line = f"{src} -> {dst} | Protocol: {proto}"
        print("[+] " + log_line)
        with open("packets.log", "a") as f:
            f.write(log_line + "\n")

def main():
    print("Starting packet capture... (Press Ctrl+C to stop)")
    # Capture packets indefinitely
    sniff(prn=process_packet)

if __name__ == "__main__":
    main()

