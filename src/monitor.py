from scapy.all import sniff, wrpcap
from aws_integration import upload_to_s3, log_to_cloudwatch, put_cloudwatch_metric
import logging

def packet_callback(packet):
    print(packet.summary())
    log_to_cloudwatch(f"Packet captured: {packet.summary()}", 'NetworkMonitorGroup', 'NetworkMonitorStream')

def start_sniffing(interface, filter=None):
    print(f"Starting packet sniffing on {interface}...")
    
    try:
        # Capture packets and store them in a list
        packets = sniff(iface=interface, prn=packet_callback, filter=filter, count=10)

        # Save the captured packets to a file
        wrpcap('captured_packets.pcap', packets)
        print("Packets captured and saved to 'captured_packets.pcap'.")

        # Upload the file to S3
        upload_to_s3('captured_packets.pcap', 'myawsbucket-zd')

        # Log metrics to CloudWatch
        put_cloudwatch_metric('NetworkMonitoring', 'TotalPacketsCaptured', len(packets))
        print(f"Captured {len(packets)} packets.")
    
    except Exception as e:
        logging.error(f"Error during packet sniffing: {e}")

if __name__ == "__main__":
    interface = "eth0"  # Replace with your actual network interface
    start_sniffing(interface)
