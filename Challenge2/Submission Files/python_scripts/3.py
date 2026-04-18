import pyshark

# Open the pcap file and apply the display filter for MQTT Publish messages received by clients
cap = pyshark.FileCapture('challenge2.pcapng', display_filter='mqtt.msgtype == 3 && mqtt.qos == 2 && ip.dst == 127.0.0.1')

# Initialize a counter for received MQTT Publish messages with QoS=2
received_publish_count = 0
client_ports = set()
topics = set()

# Iterate over each packet in the capture
for packet in cap:
    # Check if the packet has a MQTT layer
    if 'mqtt' in packet:
        mqtt_layer = packet.mqtt
        # ['hdrflags', 'msgtype', 'dupflag', 'qos', 'retain', 'len', 'topic_len', 'topic', 'msgid', 'msg']
        received_publish_count += 1
        client_ports.add(packet.tcp.srcport)
        print(mqtt_layer.field_names)
        print(mqtt_layer.topic)
        topics.add(mqtt_layer.topic)

# Print the number of received MQTT Publish messages with QoS=2
print("Number of MQTT Publish messages with QoS=2 received by clients:", received_publish_count)
print("Number of clients involved in the MQTT Publish messages with QoS=2:", len(client_ports))

cap = pyshark.FileCapture('challenge2.pcapng', display_filter='mqtt.msgtype == 3 && mqtt.qos == 2 && ip.dst == 127.0.0.1')
