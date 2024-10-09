from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

def start_sniffing(interface):
    print(f"Starting packet sniffing on {interface}...")
    sniff(iface=interface, prn=packet_callback, count=10)  # Adjust count as needed

if __name__ == "__main__":
    interface = "eth0"  # Replace with your actual network interface
    start_sniffing(interface)
