import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import re

# Define the mapping from topics to master nodes
topic_to_master = {
    'iot/temperature1': 'Master_1',
    'iot/temperature2': 'Master_2',
    'iot/temperature3': 'Master_3',
    'iot/temperature4': 'Master_4',
    'iot/temperature5': 'Master_5',
    'iot/temperature6': 'Master_6',
    'iot/temperature7': 'Master_7',
    'iot/temperature8': 'Master_8'
}

# Define the filenames and corresponding IoT devices
log_files = {
    'iot_device_log1.log': 'IoT_1',
    'iot_device_log2.log': 'IoT_2',
    'iot_device_log3.log': 'IoT_3',
    'iot_device_log4.log': 'IoT_4',
    'iot_device_log5.log': 'IoT_5',
    'iot_device_log6.log': 'IoT_6',
    'iot_device_log7.log': 'IoT_7',
    'iot_device_log8.log': 'IoT_8',
    'iot_device_log9.log': 'IoT_9',
    'iot_device_log10.log': 'IoT_10'
}

# Regular expression to match log lines
log_line_regex = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - Published transaction \w{8}-\w{4}-\w{4}-\w{4}-\w{12} to (iot/temperature\d)')

# Function to process each log file and extract relevant data
def process_log_file(filename, device_id):
    data = []
    with open(filename, 'r') as file:
        for line in file:
            print(f"Processing line: {line.strip()}")
            match = log_line_regex.match(line.strip())
            if match:
                timestamp_str, topic = match.groups()
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
                master_node = topic_to_master.get(topic)
                if master_node:
                    data.append((timestamp, device_id, master_node))
                    print(f"Added data: {(timestamp, device_id, master_node)}")
            else:
                print("Skipping line: no match found")
    return data

# Process all log files and combine the data into a single DataFrame
all_data = []
for log_file, device_id in log_files.items():
    print(f"Processing log file: {log_file}")
    all_data.extend(process_log_file(log_file, device_id))

# Print all_data to check if it is being filled correctly
print("All data:", all_data)

df = pd.DataFrame(all_data, columns=['Timestamp', 'Device', 'Master_Node'])

# Ensure the Timestamp column is of datetime type
df['Timestamp'] = pd.to_datetime(df['Timestamp'])

# Print the DataFrame to check its contents
print("DataFrame:\n", df)

# Calculate time in seconds from the start for the x-axis
start_time = df['Timestamp'].min()
df['Time_Seconds'] = (df['Timestamp'] - start_time).dt.total_seconds()

# Convert Master_Node to categorical type
df['Master_Node'] = pd.Categorical(df['Master_Node'], categories=['Master_1', 'Master_2', 'Master_3', 'Master_4', 'Master_5', 'Master_6', 'Master_7', 'Master_8'])

# Create the plot
fig, ax1 = plt.subplots(figsize=(14, 8))

# Plot data for each IoT device
colors = {
    'IoT_1': 'blue',
    'IoT_2': 'orange',
    'IoT_3': 'green',
    'IoT_4': 'red',
    'IoT_5': 'purple',
    'IoT_6': 'brown',
    'IoT_7': 'pink',
    'IoT_8': 'gray',
    'IoT_9': 'olive',
    'IoT_10': 'cyan'
}

for device_id, color in colors.items():
    device_data = df[df['Device'] == device_id]
    print(f"Data for {device_id}:\n", device_data)
    ax1.scatter(device_data['Time_Seconds'], device_data['Master_Node'], label=f'Tx {device_id}', color=color, s=70)

# Customize the plot
ax1.set_xlabel('Time (seconds)', fontsize=30)
ax1.set_ylabel('Master Nodes', fontsize=30, labelpad=15)
#ax1.set_title('Transactions Sent by IoT Devices to Master Nodes Over Time', fontsize=30)
ax1.tick_params(axis='both', which='major', labelsize=25)
ax1.set_yticks(range(8))  # Indices for the master nodes
ax1.set_yticklabels(['Master_1', 'Master_2', 'Master_3', 'Master_4', 'Master_5', 'Master_6', 'Master_7', 'Master_8'], fontsize=25)
ax1.grid(True)

# Increase the size of legend markers
handles, labels = ax1.get_legend_handles_labels()
for handle in handles:
    handle.set_sizes([150.0])

# Move the legend to the right
ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5), fontsize=20)

# Save the plot as an image file
output_file_path = 'iot_transactions_to_masters.png'
plt.savefig(output_file_path, bbox_inches='tight')
plt.show()
plt.close()
