import matplotlib.pyplot as plt
import pandas as pd

# Load the log file
log_file_path = 'master_node_events.log'

# Read the log file into a DataFrame
log_df = pd.read_csv(log_file_path, sep=' - ', header=None, names=['Timestamp', 'Event', 'Details'], engine='python')
log_df['Timestamp'] = pd.to_datetime(log_df['Timestamp'])

# Extract time in seconds from the first entry
start_time = log_df['Timestamp'].iloc[0]
log_df['Time_Seconds'] = (log_df['Timestamp'] - start_time).dt.total_seconds()

# Extract reputation updates and authority changes
reputation_updates = log_df[log_df['Event'] == 'Current Reputation']
authority_changes = log_df[log_df['Event'] == 'Authority Change']

# Parse the node IDs and reputations
reputation_updates[['Node', 'Reputation']] = reputation_updates['Details'].str.extract(r'Node: (\w+), Reputation: ([\d\.]+)')
reputation_updates['Reputation'] = reputation_updates['Reputation'].astype(float).round(2)

# Parse the authority changes
authority_changes['New_Authority'] = authority_changes['Details'].str.extract(r'New Authority: (\w+)')

# Define color mapping for each node
colors = {
    'Master_1': 'blue',
    'Master_2': 'orange',
    'Master_3': 'green',
    'Master_4': 'red'
}

# Create the plot
fig, ax2 = plt.subplots(figsize=(10, 8))

# Plot reputation updates with lines
for node in reputation_updates['Node'].unique():
    node_data = reputation_updates[reputation_updates['Node'] == node]
    ax2.plot(node_data['Time_Seconds'], node_data['Reputation'], label=f'Reputation {node}', color=colors[node])

# Plot authority changes with markers
for node in authority_changes['New_Authority'].unique():
    node_data = authority_changes[authority_changes['New_Authority'] == node]
    ax2.scatter(node_data['Time_Seconds'], [1] * len(node_data), label=f'Authority {node}', color=colors[node], zorder=5, s=50, marker='o')

# Customize the plot
ax2.set_xlabel('Time (seconds)', fontsize=30)
ax2.set_ylabel('Reputation', fontsize=30, labelpad=15)
#ax2.set_title('Master Node Reputations and Authority Changes Over Time', fontsize=25)
ax2.tick_params(axis='both', which='major', labelsize=25)
ax2.grid(True)

# Add secondary y-axis for master node identifiers
ax1 = ax2.twinx()
ax1.set_yticks([1, 2, 3, 4])
ax1.set_yticklabels(['Master_1', 'Master_2', 'Master_3', 'Master_4'], fontsize=25)
ax1.set_ylabel('Master Nodes', fontsize=30, labelpad=15)
ax1.tick_params(axis='both', which='major', labelsize=25)

# Customize legend
ax2.legend(loc='upper left', fontsize=15)

# Save the plot as an image file
output_file_path = 'master_node_reputations_authority_changes_final.png'
plt.savefig(output_file_path)
plt.show()
plt.close()
