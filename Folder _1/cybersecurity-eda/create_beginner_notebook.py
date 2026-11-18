import nbformat as nbf
import os

nb = nbf.v4.new_notebook()

cells = []

# Cell 0: Markdown Title
cells.append(nbf.v4.new_markdown_cell("""# 🔰 Beginner-Friendly Cybersecurity Data Analysis
### *Exploratory Data Analysis (EDA) on 3.96 Million Network Packets*

Welcome! This notebook is designed to be **simple, clear, and easy to understand**. 
There are **no complicated classes, no database setups, and no confusing advanced code**.

Just standard **Pandas** and **Matplotlib** to answer simple questions:
1. What does the data look like?
2. Are there missing or corrupted values?
3. What protocols are being used?
4. How large are the packets?
5. When did the cyber attack happen?
6. Who was attacking whom?
7. How can we detect the attacks using simple Python rules?
"""))

# Cell 1: Step 1 Load Data
cells.append(nbf.v4.new_markdown_cell("""### 📦 Step 1: Load the Dataset
We load the dataset using standard `pandas.read_csv()`. It has **3,962,784 packets** and loads in just about 3 seconds.
"""))

cells.append(nbf.v4.new_code_cell(r"""import pandas as pd
import matplotlib.pyplot as plt

# Path to the dataset CSV file
import os
csv_file = "data/original/Cap_1_10VM_1Apache/L1_Cap_202209051617.csv" if os.path.exists("data/original/Cap_1_10VM_1Apache/L1_Cap_202209051617.csv") else "../data/original/Cap_1_10VM_1Apache/L1_Cap_202209051617.csv"

# Load the file into a pandas DataFrame (just 1 line of code!)
print("Loading data... please wait ~3 seconds...")
df = pd.read_csv(csv_file, low_memory=False)

print(f"Done! Loaded {len(df):,} total packets.")
"""))

# Cell 2: Step 2 Inspect Data
cells.append(nbf.v4.new_markdown_cell("""### 🔍 Step 2: Look at the First Few Rows & Check for Missing Data
Let's see what columns we have and if there are any missing (NaN) values.
"""))

cells.append(nbf.v4.new_code_cell(r"""# 1. View the first 5 rows
print("--- FIRST 5 PACKETS ---")
display(df.head())

# 2. Check for missing values in each column
print("\n--- MISSING VALUES ---")
print(df.isna().sum())
"""))

# Cell 3: Step 3 Protocols
cells.append(nbf.v4.new_markdown_cell("""### 🌐 Step 3: What Protocols Are Being Used?
Let's count how many packets belong to TCP, ARP, ICMP, etc., and plot a simple bar chart.
"""))

cells.append(nbf.v4.new_code_cell(r"""# Count how many packets belong to each protocol
protocol_counts = df['Protocol'].value_counts()
print(protocol_counts)

# Draw a simple bar chart
plt.figure(figsize=(8, 4))
protocol_counts.plot(kind='bar', color='skyblue', edgecolor='black')
plt.title("Packet Counts by Protocol (Log Scale)")
plt.xlabel("Protocol")
plt.ylabel("Number of Packets")
plt.yscale('log')  # We use log scale because TCP is in the millions while others are in the hundreds
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.show()
"""))

# Cell 4: Step 4 Packet Sizes
cells.append(nbf.v4.new_markdown_cell("""### 📏 Step 4: How Big Are the Packets? (Finding the 174-byte Clue)
Let's inspect the `Length` column (packet size in bytes). 
Notice something strange: the 25%, 50% (median), and 75% are **all exactly 174 bytes**!
"""))

cells.append(nbf.v4.new_code_cell(r"""# Summary statistics for packet lengths
print(df['Length'].describe())

# Histogram of packet sizes between 0 and 1500 bytes
plt.figure(figsize=(8, 4))
plt.hist(df['Length'], bins=50, range=(0, 1500), color='salmon', edgecolor='black')
plt.title("Distribution of Packet Sizes (Notice the massive spike at 174 bytes!)")
plt.xlabel("Packet Size in Bytes")
plt.ylabel("Frequency")
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.show()
"""))

# Cell 5: Step 5 Traffic Over Time
cells.append(nbf.v4.new_markdown_cell("""### ⏰ Step 5: When Did the Attack Happen? (Traffic Over Time)
The capture lasted about 24 hours (84,714 seconds). Let's plot traffic across the entire timeline to see when the attack started.
"""))

cells.append(nbf.v4.new_code_cell(r"""# Convert seconds to hours for easier reading
df['Time_Hours'] = df['Time'] / 3600

# Group the 24 hours into 100 simple time slices and count packets in each slice
time_slices = pd.cut(df['Time_Hours'], bins=100)
traffic_timeline = df.groupby(time_slices, observed=False).size()

# Plot the timeline
plt.figure(figsize=(10, 4))
plt.plot(range(len(traffic_timeline)), traffic_timeline.values, color='crimson', linewidth=1.8)
plt.title("Network Traffic Across 24 Hours (Notice the huge spike at Hour 23!)")
plt.xlabel("Time Progress (Bins across 24 Hours)")
plt.ylabel("Packets Count")
plt.grid(True, linestyle='--', alpha=0.6)
plt.show()
"""))

# Cell 6: Step 6 Attackers and Targets
cells.append(nbf.v4.new_markdown_cell("""### 🎯 Step 6: Who is Attacking Whom? (Top IPs)
Let's see which Destination IP received the most traffic, and which Source IPs sent the most traffic.
"""))

cells.append(nbf.v4.new_code_cell(r"""print("--- TOP 5 TARGET (DESTINATION) IPs ---")
print(df['Destination'].value_counts().head(5))

print("\n--- TOP 5 SENDER (SOURCE) IPs ---")
print(df['Source'].value_counts().head(5))
"""))

# Cell 7: Step 7 Simple Detection Rules
cells.append(nbf.v4.new_markdown_cell("""### 🛡️ Step 7: Simple Attack Detection Rules
We can detect the attacks with just simple Pandas filtering rules!
1. **DDoS SYN Flood:** Over 3.4 million identical 174-byte packets targeting `172.17.0.2`.
2. **Port Scan Rejections:** ICMP error packets generated when someone scans closed ports.
"""))

cells.append(nbf.v4.new_code_cell(r"""# Rule 1: Flag all 174-byte packets attacking the web server (172.17.0.2)
ddos_packets = df[(df['Length'] == 174) & (df['Destination'] == '172.17.0.2')]

print(f"🚨 Detected DDoS Attack Packets: {len(ddos_packets):,}")
print(f"Percentage of Total Traffic: {len(ddos_packets) / len(df) * 100:.2f}%")

# Rule 2: Flag ICMP Error responses from closed ports
port_scan_packets = df[df['Protocol'] == 'ICMP']
print(f"🚨 Detected Port Scan Error Packets: {len(port_scan_packets):,}")
"""))

nb['cells'] = cells

out_notebook = "notebooks/beginner_cybersecurity_eda.ipynb"
with open(out_notebook, "w") as f:
    nbf.write(nb, f)

print(f"Successfully created: {out_notebook}")
