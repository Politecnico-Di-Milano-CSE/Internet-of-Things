import pyshark

cap = pyshark.FileCapture('challenge2.pcapng', display_filter='coap && (udp.dstport == 55898 || udp.dstport == 33677 || udp.dstport == 51812 || udp.dstport == 48049 || udp.dstport == 52276 || udp.dstport == 48645 || udp.dstport == 52247 || udp.dstport == 41264)')

# Initialize variables to store the longest response length and its associated Message ID
longest_response_length = 0
longest_response_mid = None

# Iterate over each packet in the capture
for packet in cap:
    # Check if the packet has a CoAP layer
    if 'coap' in packet:
        coap_layer = packet.coap
        # Check if it's a response packet and has a payload
        if hasattr(coap_layer, 'payload') and coap_layer.payload:
            # If the payload length is longer than the longest recorded, update the variables
            if len(coap_layer.payload.binary_value) > longest_response_length:
                longest_response_length = len(coap_layer.payload.binary_value)
                longest_response_mid = coap_layer.mid

# Print the Message ID of the longest CoAP response
print("Message ID (MID) of the longest CoAP response:", longest_response_mid)
