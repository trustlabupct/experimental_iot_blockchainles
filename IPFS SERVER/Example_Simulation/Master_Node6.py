"""
This script is for an IoT system that generates transactions, sends them to master nodes, and manages the state of the network. It includes functionalities for connecting to an IPFS server, handling MQTT messages, maintaining a DAG, and visualizing node reputations in real-time.
"""

import json
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PrivateFormat, NoEncryption, PublicFormat
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
import random
import threading
import time
import signal
import sys
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import requests
import networkx as nx
import ipfshttpclient
import hashlib

# Configuration and Initialization
node_id = "node_006"    #CHANGE ID
topic_temperature = "temperature6"  #CHANGE TOPIC
other_nodes = []  # List of other master nodes in the network
reputation = {node_id: 10}  # Initial reputation for this node
weights = {node_id: 1.0}  # Initial weight for this node
node_joined_time = {node_id: time.time()}  # Record when each node joined
node_last_active = {node_id: time.time()}  # Record the last activity of each node
transactions_received = 0
transactions_added_to_dag = 0

# Graph and DAG Setup
dag = nx.DiGraph()  # NetworkX graph for visualization

def send_data_to_ipfs(transaction_data):
    """
    Sends transaction data to an IPFS server and returns the response.
    """
    try:
        client_ipfs = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001/http')
        res = client_ipfs.add_json(transaction_data)
        print("IPFS Server Response:", res)  # Debug message
        return res
    except Exception as e:
        print(f"Error sending data to IPFS: {e}")
        return None

def print_transaction_summary():
    """
    Prints a summary of transactions.
    """
    print("Transaction Summary:")
    print(f"Transactions received: {transactions_received}")
    print(f"Transactions added to the DAG: {transactions_added_to_dag}")

def handle_exit_signal(signum, frame):
    """
    Handles the exit signal for graceful shutdown.
    """
    print("Received stop signal, printing transaction summary...")
    print_transaction_summary()
    publish_master_availability(False)  # Announce that this node is no longer available for IoT
    announce_departure()  # Inform other masters of the disconnection
    client.disconnect()  # Properly disconnect the MQTT client
    print("Cleanup completed, the program will now terminate.")
    sys.exit(0)

def announce_departure():
    """
    Announces to other masters that this node is leaving the network.
    """
    departure_data = json.dumps({"node_id": node_id, "action": "leave"})
    client.publish("network/presence", departure_data)

class Node:
    """
    Represents a node in the DAG.
    """
    def __init__(self, node_id, data):
        self.node_id = node_id
        self.data = data  # Ensure to store the correct data
        self.parents = []  # List of parent nodes' IDs

    def __str__(self):
        parent_ids = [parent.node_id for parent in self.parents]  # Assume parents are also Node objects
        return f"Node ID: {self.node_id}, Data: {self.data}, Parents: {parent_ids}"

class Graph:
    """
    Represents a Directed Acyclic Graph (DAG) for managing nodes and edges.
    """
    def __init__(self):
        self.nodes = {}
        self.nx_graph = nx.DiGraph()  # NetworkX graph for visualization

    def add_node(self, node_id, data):
        """
        Adds a new node to the DAG.
        """
        if node_id not in self.nodes:
            new_node = Node(node_id, data)
            self.nodes[node_id] = new_node
            self.nx_graph.add_node(node_id)
            print(f"Node {node_id} added to DAG")
            self.assign_parents(node_id)  # Assign parents and create edges in NetworkX

    def assign_parents(self, new_node_id):
        """
        Assigns parents to a new node based on the current state of the DAG.
        """
        if len(self.nx_graph.nodes) > 1:
            # Select nodes with the fewest parents to be parents of the new node
            candidates = sorted(
                (n for n in self.nx_graph.nodes if n != new_node_id),
                key=lambda n: len(self.nodes[n].parents)
            )[:2]  # Take the two nodes with the fewest parents
            for parent_id in candidates:
                self.nx_graph.add_edge(parent_id, new_node_id)
                parent_node = self.nodes[parent_id]
                parent_node.parents.append(self.nodes[new_node_id])  # Add the new node to the parent's list

def visualize_dag(nx_graph):
    """
    Visualizes the current state of the DAG.
    """
    plt.figure(f"DAG - {node_id}", figsize=(12, 8))
    pos = nx.spring_layout(nx_graph)  # Use NetworkX DiGraph directly
    labels = {node: f'{node[:6]}...{node[-6:]}' for node in nx_graph.nodes()}  # Create shorter labels
    nx.draw(nx_graph, pos, labels=labels, with_labels=True, node_color='lightblue', node_size=500, font_size=8, font_weight='bold')
    plt.title(f'DAG - {node_id}')
    plt.show()

def periodic_visualization(graph):
    """
    Periodically visualizes the DAG.
    """
    subgraph_nodes = list(graph.nx_graph.nodes)[-100:]  # Last 100 nodes
    subgraph = graph.nx_graph.subgraph(subgraph_nodes)
    #UNCOMMENT FOR DRAW DAG IMAGE
    #visualize_dag(subgraph)  # Pass the correct subgraph
    threading.Timer(20, periodic_visualization, args=(graph,)).start()

dag = Graph()  # Graph instance
client = mqtt.Client()  # MQTT client

def on_connect(client, userdata, flags, rc):
    """
    Callback function for when the client connects to the broker.
    Subscribes to general and specific topics.
    """
    print(f"Connected with result code {rc}")
    client.subscribe(f"iot/{topic_temperature}")
    client.subscribe("network/validated_transactions")
    client.subscribe("network/presence")
    client.subscribe("network/heartbeat")
    client.subscribe("network/updates/#")
    client.subscribe("network/confirmations")
    client.subscribe(f"network/nodes/{node_id}")
    periodic_state_update()  # Start state update timer

signal.signal(signal.SIGINT, handle_exit_signal)
signal.signal(signal.SIGTERM, handle_exit_signal)

def on_message(client, userdata, msg):
    """
    Callback function for when a message is received on a subscribed topic.
    """
    data = json.loads(msg.payload)
    topic_parts = msg.topic.split('/')
    if msg.topic == f"iot/{topic_temperature}":
        process_iot_message(data)
    elif msg.topic == "network/validated_transactions":
        process_peer_message(data)
    elif msg.topic == "network/presence":
        handle_presence_message(data)
    elif msg.topic == "network/heartbeat":
        handle_heartbeat(data)
    elif topic_parts[1] == "nodes" and topic_parts[2] == node_id:
        handle_direct_message(data)
    elif topic_parts[1] == "updates":
        on_update_received(client, userdata, msg)
    elif msg.topic == "network/confirmations":
        on_confirmation_received(client, userdata, msg)

def announce_presence():
    """
    Announces the presence of this node to the network.
    """
    presence_data = json.dumps({
        "node_id": node_id,
        "action": "join",
        "weights": weights[node_id]
    })
    client.publish("network/presence", presence_data)
    threading.Timer(300, announce_presence).start()

def publish_master_availability(available=True):
    """
    Publishes the availability of this node to IoT devices.
    """
    status = "available" if available else "unavailable"
    availability_data = json.dumps({
        "node_id": node_id,
        "status": status,
        "topic": f"iot/{topic_temperature}"
    })
    client.publish("network/master_presence", availability_data)
    threading.Timer(17, publish_master_availability).start()

def handle_presence_message(data):
    """
    Handles presence messages from other nodes.
    """
    node = data['node_id']
    if data['action'] == "join" and node != node_id:
        if node not in other_nodes:
            other_nodes.append(node)
            node_joined_time[node] = time.time()
            node_last_active[node] = time.time()
        reputation[node] = 10
        weights[node] = data['weights']
        print(f"Node {node} joined the network with weight {weights[node]}.")
    elif data['action'] == "leave" and node != node_id:
        if node in other_nodes:
            other_nodes.remove(node)
        reputation.pop(node, None)
        weights.pop(node, None)
        print(f"Node {node} left the network.")
        select_authority()
        publish_master_availability(False)
        announce_presence()

def handle_heartbeat(data):
    """
    Handles heartbeat messages to update node activity.
    """
    node = data['node_id']
    if node != node_id and node not in other_nodes:
        other_nodes.append(node)
        node_joined_time[node] = time.time()
    node_last_active[node] = time.time()

def send_heartbeat():
    """
    Sends heartbeat messages to indicate node is active.
    """
    heartbeat_data = json.dumps({"node_id": node_id})
    client.publish("network/heartbeat", heartbeat_data)
    threading.Timer(10, send_heartbeat).start()

def decay_reputation():
    """
    Decreases the reputation of inactive nodes every 10 minutes.
    """
    current_time = time.time()
    for node, last_active in node_last_active.items():
        if current_time - last_active > 600:  # 10 minutes of inactivity
            reputation[node] = max(reputation[node] - 1, 0)
    threading.Timer(600, decay_reputation).start()

def process_iot_message(data):
    """
    Processes incoming IoT messages and validates transactions.
    """
    global transactions_received
    transactions_received += 1
    node_last_active[node_id] = time.time()
    if validate_transaction(data['data'], data['signature'], data['public_key']):
        update_reputation(node_id, 2)
        authority = select_authority()
        if authority == node_id:
            print("\033[91mI am the authority.\033[0m")
            received_hash = add_transaction_to_dag(data)  # Assumes it returns the new node hash
            if received_hash:
                dag.assign_parents(received_hash)
        else:
            print(f"\033[91mThe authority is now: {authority}.\033[0m")
            forward_to_authority(data)
    else:
        update_reputation(node_id, -1)
        print("Validation failed.")

def handle_direct_message(data):
    """
    Handles direct messages sent specifically to this node.
    """
    if validate_transaction(data['data'], data['signature'], data['public_key']):
        update_reputation(node_id, 0.1)
        if select_authority() == node_id:
            add_transaction_to_dag(data)
        else:
            forward_to_authority(data)
    else:
        update_reputation(node_id, -1)
        print("Validation failed.")

def add_transaction_to_dag(transaction_data):
    """
    Adds a validated transaction to the DAG.
    """
    global transactions_added_to_dag

    # Add node_id to the transaction data
    transaction_data['data']['node_id'] = node_id

    # Prepare data for signing
    data_to_sign = json.dumps(transaction_data['data']).encode('utf-8')
    signature = sign_data(private_key, data_to_sign)  # Ensure this function returns hex

    # Send data to IPFS server including signature and public key
    received_hash = send_data_to_ipfs(transaction_data['data'])

    if received_hash is None:
        print("Error obtaining hash from server, aborting.")
        return None

    # If the hash is correct, add only the hash to the DAG as a node
    if received_hash not in dag.nodes:
        dag.add_node(received_hash, {'hash': received_hash, 'node_id': node_id})
        transactions_added_to_dag += 1
        print(f"Transaction hash verified and added to DAG as a unique node.")
        notify_peers(transaction_data['data'], received_hash)
        return received_hash

    return None

def process_peer_message(data):
    """
    Processes incoming messages from other peers.
    """
    global transactions_added_to_dag

    received_hash = data['hash']
    transaction_id = data['transaction_id']

    if received_hash not in dag.nodes:
        dag.add_node(received_hash, {'hash': received_hash})  # Add the node to the DAG
        dag.assign_parents(received_hash)  # Assign parents after adding the node
        transactions_added_to_dag += 1
        print(f"Transaction received from another peer validated with hash and added to DAG.")

def validate_transaction(data_json, signature_dict, public_key_pem):
    """
    Validates a transaction by verifying its signature.
    """
    try:
        signature_bytes = bytes.fromhex(signature_dict['signature'])
        data_encoded = json.dumps(data_json).encode('utf-8')
        public_key = load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        public_key.verify(signature_bytes, data_encoded, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def update_reputation(node_id, change):
    """
    Updates the reputation of a node.
    """
    reputation[node_id] = reputation.get(node_id, 10) + change

def select_authority():
    """
    Selects the authoritative node based on reputation and other factors.
    """
    now = time.time()
    total_weighted_reputation = 0
    probabilities = {}
    max_reputation = -1
    candidates = []

    for n, rep in reputation.items():
        age_factor = 2.0 if (now - node_joined_time.get(n, now)) < 604800 else 1.0  # Boost during the first week
        effective_reputation = rep * weights[n] * age_factor
        probabilities[n] = effective_reputation
        total_weighted_reputation += effective_reputation

        if effective_reputation > max_reputation:
            max_reputation = effective_reputation
            candidates = [n]
        elif effective_reputation == max_reputation:
            candidates.append(n)

    if total_weighted_reputation == 0 or len(candidates) > 1:
        selected_node = random.choice(candidates)
    else:
        selected_node = candidates[0]

    return selected_node

def notify_peers(transaction_data, hash_sha256):
    """
    Notifies other peers about a validated transaction.
    """
    data_to_send = {
        'hash': hash_sha256,
        'transaction_id': transaction_data['transaction_id'],
        'device_id': transaction_data['device_id'],
        'temperature': transaction_data['temperature'],
        'timestamp': transaction_data['timestamp']
    }
    client.publish("network/validated_transactions", json.dumps(data_to_send))

def forward_to_authority(data):
    """
    Forwards a transaction to the authoritative node.
    """
    authority = select_authority()
    if authority != node_id:
        client.publish(f"network/nodes/{authority}", json.dumps(data))

def broadcast_updates():
    """
    Sends state updates to all nodes.
    """
    update_data = {
        'node_id': node_id,
        'reputation': reputation[node_id],
        'weights': weights[node_id],
        'timestamp': time.time()
    }
    for node in other_nodes:
        client.publish(f"network/updates/{node}", json.dumps(update_data))

def on_update_received(client, userdata, msg):
    """
    Handles received state updates from other nodes.
    """
    data = json.loads(msg.payload)
    node = data['node_id']
    if node != node_id and (node not in confirmed_updates or confirmed_updates[node] < data['timestamp']):
        reputation[node] = data['reputation']
        weights[node] = data['weights']
        confirmed_updates[node] = data['timestamp']
        client.publish(f"network/confirmations/{node}", json.dumps({'node_id': node_id}))

def on_confirmation_received(client, userdata, msg):
    """
    Processes confirmations from other nodes.
    """
    data = json.loads(msg.payload)
    confirmed_node_id = data['node_id']
    confirmed_updates[confirmed_node_id] = time.time()

def periodic_state_update():
    """
    Sends periodic state updates and manages reputation decay.
    """
    broadcast_updates()
    decay_reputation()
    threading.Timer(1, periodic_state_update).start()

confirmed_updates = {}

def are_updates_synced():
    """
    Checks if all nodes have confirmed receiving the latest updates.
    """
    return len(confirmed_updates) == len(other_nodes)

# Key generation
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

def sign_data(private_key, data):
    """
    Signs data using ECDSA and returns the signature in hex format.
    """
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature.hex()

# Configuration for live reputation chart
fig, ax = plt.subplots()
plt.title('Live Reputation Chart')
plt.xlabel('Nodes')
plt.ylabel('Reputation')

def update_graph():
    """
    Updates the reputation graph.
    """
    ax.clear()
    nodes = list(reputation.keys())
    reputations = list(reputation.values())
    colors = ['blue' if rep < max(reputations) else 'red' for rep in reputations]  # Red for max reputation
    ax.bar(nodes, reputations, color=colors)
    plt.xticks(rotation=45, ha="right")
    ax.set_ylim(0, max(reputations) + 5)

def animate(i):
    """
    Animation function for the live reputation chart.
    """
    update_graph()

def run_animation():
    """
    Runs the animation for the live reputation chart.
    """
    ani = FuncAnimation(fig, animate, interval=1000)  # Update every 1 second
    plt.show()

# Run the animation in a separate thread to avoid blocking
#animation_thread = threading.Thread(target=run_animation)
#animation_thread.start()

if __name__ == "__main__":
    try:
        client.on_connect = on_connect
        client.on_message = on_message
        client.connect("localhost", 1883, 60)
        client.loop_start()

        announce_presence()
        send_heartbeat()
        decay_reputation()  # Start periodic reputation decay
        publish_master_availability()  # Announce to IoT devices
        periodic_visualization(dag)  # Start periodic DAG visualization

        # Keep the script running in an infinite loop
        while True:
            time.sleep(1)

    except Exception as e:
        print(f"Unhandled error: {e}")
