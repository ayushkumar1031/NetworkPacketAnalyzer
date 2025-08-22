# NetworkPacketAnalyzer
A simple Python program that captures network packets (TCP, UDP, ICMP) and shows their source, destination, and protocol. This project helps understand how data flows over a network and gives hands-on experience with packet analysis.
data flows over a network and gives hands-on experience with packet analysis.
Features:
Capture TCP, UDP, and ICMP packets
Display source and destination IP addresses
Log packet details to a file
Beginner-friendly and easy to use
How It Works:
The program uses Python’s Scapy library to capture packets. Each packet is checked for the IP layer, and the protocol type (TCP, UDP, ICMP) is identified. Packet details are printed on the terminal and also saved in a file called packets.log. You can stop the capture anytime by pressing Ctrl+C.

Setup & Run:
Install Python 3 and the Scapy library:
pip install scapy
Run the program (you might need admin/root privileges):
sudo python analyzer.py
Watch packet details appear in the terminal and in packets.log.

My Learnings:
Learned how network packets are structured and transmitted over TCP/IP
Gained hands-on experience with Python’s Scapy library
Learned how to filter and log packets programmatically
Improved debugging and problem-solving skills while analyzing network traffic
Output Example:
[+] 192.168.1.5 -> 142.250.190.78 | Protocol: TCP
[+] 192.168.1.5 -> 142.250.190.78 | Protocol: UDP
