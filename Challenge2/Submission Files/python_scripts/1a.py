import pyshark

# Open the pcap file and apply the display filter for CoAP GET requests to the temperature resource
cap = pyshark.FileCapture('challenge2.pcapng', display_filter='coap && coap.code == 1 && coap.opt.uri_path contains "temperature"')

# Count unique source ports
unique_clients = set()

for packet in cap:
    unique_clients.add(packet.udp.srcport)

# Count the number of unique clients
num_clients = len(unique_clients)

print("Number of different CoAP clients that sent a GET request to a temperature resource: ", num_clients)

