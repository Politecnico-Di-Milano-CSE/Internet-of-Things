import pyshark

topic = "metaverse/facility4/area0/light"
capture_file = "challenge2.pcapng"
match_counter = 0

def match_topic_subscription(subscription, topic):
    """
    Determine whether a topic subscription matches a topic.

    Args:
        subscription (str): The topic subscription, which may contain wildcards (+ and #).
        topic (str): The topic to be matched against the subscription.

    Returns:
        bool: True if the topic matches the subscription, False otherwise.
    """
    # Split the subscription and topic into segments
    sub_segments = subscription.split('/')
    topic_segments = topic.split('/')

    # Iterate over each segment of the subscription and topic
    for sub_seg, topic_seg in zip(sub_segments, topic_segments):
        # If the segment in the subscription is '+', it matches any single segment in the topic
        if sub_seg == '+':
            continue
        # If the segment in the subscription is '#', it matches any remaining segments in the topic
        elif sub_seg == '#':
            return True
        # If the segments are not equal and the subscription segment is not a wildcard, they don't match
        elif sub_seg != topic_seg:
            return False

    # If all segments match up to this point and the lengths match or the last subscription segment is '#', it's a match
    return len(sub_segments) == len(topic_segments) or sub_segments[-1] == '#'

# Initialize a set to store unique source ports
source_ports = set()

# Open the pcap file and apply the display filter for CoAP requests to the "coap.me" server
cap = pyshark.FileCapture(capture_file, display_filter='mqtt.msgtype == 8 && (mqtt.topic contains "+" || mqtt.topic contains "#") && ip.src != 127.0.0.1')

# Iterate over each packet in the capture to collect request tokens
for packet in cap:
    # Check if the packet has a CoAP layer
    if 'mqtt' in packet:
        mqtt_layer = packet.mqtt
        source_ports.add(packet.tcp.srcport)
        if match_topic_subscription(mqtt_layer.topic, topic):
            match_counter = match_counter + 1

print(len(source_ports))
print(match_counter)

