from scapy.all import IP, TCP, send
import time

print("[*] Sending simulated plaintext password packet to local interface...")

# Constructing a simulated raw layer 7 payload containing the leak keywords
fake_payload = "POST /login HTTP/1.1\r\nHost: localtest.org\r\n\r\nuser=admin&password=SecretPassword123"

# Creating a local loop packet (From your IP to your IP)
packet = IP(dst="127.0.0.1")/TCP(sport=12345, dport=80)/fake_payload

# Sending the packet over the network layer
send(packet, verbose=False)

print("[+] Packet sent successfully! Check your sniffer console.")
