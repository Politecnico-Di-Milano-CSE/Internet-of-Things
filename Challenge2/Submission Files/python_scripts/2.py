import pyshark

capture_file = "challenge2.pcapng"

# Filter for CoAP POST requests to "coap.me"
cap = pyshark.FileCapture(capture_file, display_filter='coap && ip.dst == 134.102.218.18 && coap.code == 2')

request_tokens = {}

# Collect tokens from POST requests
for packet in cap:
    if 'coap' in packet:
        coap_layer = packet.coap
        if hasattr(coap_layer, 'token'):
            # Assume failure initially for each request
            request_tokens[coap_layer.token] = False

# Analyze responses from "coap.me"
cap = pyshark.FileCapture(capture_file, display_filter='coap && ip.src == 134.102.218.18')

# Iterate to find successful responses
for packet in cap:
    if 'coap' in packet:
        coap_layer = packet.coap
        # Check for successful response codes (2.xx success)
        if hasattr(coap_layer, 'token') and 64 <= int(coap_layer.code) <= 95:
            token = coap_layer.token
            if token in request_tokens:
                request_tokens[token] = True

# Count unsuccessful requests
unsuccessful_count = sum(1 for status in request_tokens.values() if not status)

print("Number of unsuccessful CoAP POST requests to 'coap.me':", unsuccessful_count)

# Reset the capture for CoAP POST requests to "coap.me"
cap = pyshark.FileCapture(capture_file, display_filter='coap && ip.dst == 134.102.218.18 && coap.code == 2')

weird_resource_count = 0

# Collect tokens from POST requests
for packet in cap:
    if 'coap' in packet:
        coap_layer = packet.coap
        if hasattr(coap_layer, 'token'):
            if coap_layer.token in request_tokens and request_tokens[coap_layer.token] == False:
                # Check if it's a CoAP request and if the request URI path contains "weird" at the end
                if hasattr(coap_layer, 'opt_uri_path'):
                    uri_path = coap_layer.opt_uri_path
                    # Split the URI path into segments
                    uri_path_segments = uri_path.split(',')
                    # Check if the last segment starts with "weird"
                    if uri_path_segments and uri_path_segments[-1].startswith("weird"):
                        weird_resource_count += 1

print("Number of unsuccessful CoAP POST requests to 'weird' resources:", weird_resource_count)
