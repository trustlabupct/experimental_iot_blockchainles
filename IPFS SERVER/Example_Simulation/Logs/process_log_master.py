import matplotlib.pyplot as plt
import pandas as pd

# Load the log file
log_file_path = 'master_node_events.log'

# Read the log file into a DataFrame
log_df = pd.read_csv(log_file_path, sep=' - ', header=None, names=['Timestamp', 'Event', 'Details'], engine='python')
log_df['Timestamp'] = pd.to_datetime(log_df['Timestamp'], infer_datetime_format=True, errors='coerce')

# Extract time in seconds from the first entry
start_time = log_df['Timestamp'].iloc[0]
log_df['Time_Seconds'] = (log_df['Timestamp'] - start_time).dt.total_seconds()

# Extract reputation updates and authority changes
reputation_updates = log_df[log_df['Event'] == 'Current Reputation'].copy()
authority_changes = log_df[log_df['Event'] == 'Authority Change'].copy()

# Parse the node IDs and reputations
reputation_updates[['Node', 'Reputation']] = reputation_updates['Details'].str.extract(r'Node: (\w+), Reputation: ([\d\.]+)')
reputation_updates['Reputation'] = reputation_updates['Reputation'].astype(float).round(2)

# Parse the authority changes
authority_changes['New_Authority'] = authority_changes['Details'].str.extract(r'New Authority: (\w+)')

# Verify unique node names
print("Unique nodes in reputation updates:", reputation_updates['Node'].unique())
print("Unique nodes in authority changes:", authority_changes['New_Authority'].unique())

# Define color mapping for each node
colors = {
    'node_001': 'blue',
    'node_002': 'orange',
    'node_003': 'green',
    'node_004': 'red',
    'node_005': 'purple',
    'node_006': 'brown',
    'node_007': 'pink',
    'node_008': 'gray'
}

# Mapping from node_00X to Master_X
node_to_master = {
    'node_001': 'Master_1',
    'node_002': 'Master_2',
    'node_003': 'Master_3',
    'node_004': 'Master_4',
    'node_005': 'Master_5',
    'node_006': 'Master_6',
    'node_007': 'Master_7',
    'node_008': 'Master_8'
}

# Create the plot
fig, ax2 = plt.subplots(figsize=(12, 8))

# Plot reputation updates with lines
for node in reputation_updates['Node'].unique():
    node_data = reputation_updates[reputation_updates['Node'] == node]
    ax2.plot(node_data['Time_Seconds'], node_data['Reputation'], label=f'Reputation {node_to_master[node]}', color=colors.get(node, 'black'))

# Plot authority changes with markers
for node in authority_changes['New_Authority'].unique():
    node_data = authority_changes[authority_changes['New_Authority'] == node]
    ax2.scatter(node_data['Time_Seconds'], [1] * len(node_data), label=f'Authority {node_to_master[node]}', color=colors.get(node, 'black'), zorder=5, s=50, marker='o')

# Customize the plot
ax2.set_xlabel('Time (seconds)', fontsize=30)
ax2.set_ylabel('Reputation', fontsize=30, labelpad=15)
# ax2.set_title('Master Node Reputations and Authority Changes Over Time', fontsize=25)
ax2.tick_params(axis='both', which='major', labelsize=25)
ax2.grid(True)

# Add secondary y-axis for master node identifiers
ax1 = ax2.twinx()
ax1.set_yticks(range(1, 9))
ax1.set_yticklabels([f'Master_{i}' for i in range(1, 9)], fontsize=20)
ax1.set_ylabel('Master Nodes', fontsize=30, labelpad=15)
ax1.tick_params(axis='both', which='major', labelsize=25)

# Customize legend
#ax2.legend(loc='best', bbox_to_anchor=(0.5, 1.4), fontsize=25, ncol=3)

# Adjust layout to make room for the legend
#plt.tight_layout(rect=[0.5, 0.5, 1, 0.95])

# Save the plot as an image file
output_file_path = 'master_node_reputations_authority_changes_final.png'
plt.savefig(output_file_path)
plt.show()
plt.close()
