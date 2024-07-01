"""
This script is for an IoT device that generates transactions and sends them to randomly selected available master nodes. It also receives status messages from the master nodes to know their availability and manage which nodes to send data to.
"""

import paho.mqtt.client as mqtt
import json
import time
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import random
import uuid
import threading  # Import threading to manage timers
import logging

# MQTT Configuration
client = mqtt.Client()

# Global pause state
pause_publishing = False
active_topics = {}
timeout_seconds = 17  # Topic expiration time in seconds

# Logging Configuration
log_file = 'iot_device_log3.log'
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

def on_connect(client, userdata, flags, rc):
    """
    Called when the client connects to the broker.
    Subscribes to the 'network/master_presence' topic.
    """
    print("Connected with result code " + str(rc))
    client.subscribe("network/master_presence")

def handle_topic_timeout(topic):
    """
    Handles the expiration of a topic's lifetime.
    Removes the topic from the active_topics dictionary.
    """
    print(f"Topic {topic} timed out. Removing from active topics.")
    if topic in active_topics:
        del active_topics[topic]

def on_message(client, userdata, message):
    """
    Called when a message is received on a subscribed topic.
    Updates the active topics based on the received status.
    """
    global pause_publishing
    data = json.loads(message.payload)
    topic = data.get('topic', None)
    if data['status'] == "available":
        if topic and topic not in active_topics:
            # Restart or set the timer for the topic
            timer = threading.Timer(timeout_seconds, handle_topic_timeout, [topic])
            timer.start()  # Start the timer
            active_topics[topic] = timer  # Store the timer
    elif data['status'] == "unavailable":
        if topic in active_topics:
            active_topics[topic].cancel()  # Stop the timer
            del active_topics[topic]  # Remove the topic
            pause_publishing = True
            print(f"Pausing due to {topic} unavailability. Waiting 20 seconds.")
            time.sleep(10)  # Pause publishing for 20 seconds
            pause_publishing = False
    print(f"Active topics updated: {list(active_topics.keys())}")

# Assign the callback functions to the MQTT client
client.on_connect = on_connect
client.on_message = on_message

# Connect to the MQTT broker
client.connect("localhost", 1883, 60)
client.loop_start()

# Generate ECDSA key
private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
public_key = private_key.public_key()

def sign_data(private_key, data):
    """
    Signs the data using ECDSA and returns the signature in hex format.
    """
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return {'signature': signature.hex()}

def publish_temperature():
    """
    Generates temperature data and publishes it to a randomly selected active topic.
    Handles signing of data and ensures data is only published when masters are available.
    """
    global transacciones
    transacciones = 0
    while True:
        if not pause_publishing and active_topics:
            temperature = round(random.uniform(10, 35), 2)
            timestamp = datetime.now().isoformat()
            transaction_id = str(uuid.uuid4())
            data = {
                'transaction_id': transaction_id,
                'device_id': "IoT_3", #CHANGE DEVICE ID
                'timestamp': timestamp,
                'temperature': temperature
            }
            data_encoded = json.dumps(data).encode('utf-8')
            signature = sign_data(private_key, data_encoded)
            message = {
                'data': data,
                'signature': signature,
                'public_key': public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
            }
            # Randomly select an active topic
            selected_topic = random.choice(list(active_topics.keys()))
            client.publish(selected_topic, json.dumps(message))
            print(f"Published temperature {temperature} to {selected_topic}")
            logging.info(f"Published transaction {transaction_id} to {selected_topic}")
            transacciones += 1
        else:
            print("Publishing paused or no active master nodes available.")
        time.sleep(3)  # Interval between sends

try:
    publish_temperature()
except KeyboardInterrupt:
    print(f"\nTransactions sent: {transacciones}")
