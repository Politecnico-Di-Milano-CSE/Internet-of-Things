import pyshark

capture_file = "challenge2.pcapng"

# Initialize a set to store unique source ports
source_ports = set()

# Open the pcap file and apply the display filter for CoAP requests to the "coap.me" server
cap = pyshark.FileCapture(capture_file, display_filter='mqtt.msgtype == 8 && (mqtt.topic contains "+" || mqtt.topic contains "#") && ip.src != 127.0.0.1')

# Iterate over each packet in the capture to collect request tokens
for packet in cap:
    # Check if the packet has a CoAP layer
    if 'mqtt' in packet:
        source_ports.add(packet.tcp.srcport)

print(len(source_ports))

