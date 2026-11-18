import pandas as pd
import matplotlib.pyplot as plt

# ==========================================
# STEP 1: Load the dataset (Simple 1-liner!)
# ==========================================
print("Loading data... (takes ~3 seconds)")
csv_file = "data/original/Cap_1_10VM_1Apache/L1_Cap_202209051617.csv"
df = pd.read_csv(csv_file, low_memory=False)

print(f"Loaded {len(df):,} packets successfully!\n")

# ==========================================
# STEP 2: Quick look at the data
# ==========================================
print("--- FIRST 5 ROWS ---")
print(df.head())

print("\n--- DATA COLUMNS AND TYPES ---")
print(df.info())

print("\n--- MISSING VALUES PER COLUMN ---")
print(df.isna().sum())

# ==========================================
# STEP 3: What protocols are being used?
# ==========================================
print("\n--- PROTOCOL COUNTS ---")
proto_counts = df['Protocol'].value_counts()
print(proto_counts)

# Simple Bar Chart for Protocols
plt.figure(figsize=(7, 4))
proto_counts.plot(kind='bar', color='skyblue', edgecolor='black')
plt.title("Number of Packets by Protocol")
plt.xlabel("Protocol")
plt.ylabel("Packet Count")
plt.yscale('log') # Log scale because TCP is huge!
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()
plt.savefig("results/figures/beginner_protocols.png")
print("\nSaved chart: results/figures/beginner_protocols.png")

# ==========================================
# STEP 4: Look at Packet Sizes (Length)
# ==========================================
print("\n--- PACKET SIZE SUMMARY (IN BYTES) ---")
print(df['Length'].describe())

# Simple Histogram of Packet Sizes
plt.figure(figsize=(8, 4))
plt.hist(df['Length'], bins=50, range=(0, 1600), color='salmon', edgecolor='black')
plt.title("Distribution of Packet Sizes (Notice the huge spike at 174 bytes!)")
plt.xlabel("Packet Length (Bytes)")
plt.ylabel("Count")
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()
plt.savefig("results/figures/beginner_packet_sizes.png")
print("Saved chart: results/figures/beginner_packet_sizes.png")

# ==========================================
# STEP 5: Traffic Over Time (Finding the Attack Spike)
# ==========================================
# Convert time from seconds to hours so it's easy to read
df['Time_Hours'] = df['Time'] / 3600

# Group into 100 simple time bins to see traffic flow across the 24 hours
time_bins = pd.cut(df['Time_Hours'], bins=100)
traffic_over_time = df.groupby(time_bins, observed=False).size()

plt.figure(figsize=(10, 4))
plt.plot(range(len(traffic_over_time)), traffic_over_time.values, color='red', linewidth=1.5)
plt.title("Traffic Over Time (Notice the huge attack spike near hour 23!)")
plt.xlabel("Time Progress Across the 24 Hours")
plt.ylabel("Packets per Time Bin")
plt.grid(True, linestyle='--', alpha=0.5)
plt.tight_layout()
plt.savefig("results/figures/beginner_traffic_over_time.png")
print("Saved chart: results/figures/beginner_traffic_over_time.png")

# ==========================================
# STEP 6: Who is attacking? (Top Sources & Targets)
# ==========================================
print("\n--- TOP 5 TARGET (DESTINATION) IPs ---")
print(df['Destination'].value_counts().head(5))

print("\n--- TOP 5 SENDER (SOURCE) IPs ---")
print(df['Source'].value_counts().head(5))

# ==========================================
# STEP 7: Simple Attack Detection (Beginner Rules)
# ==========================================
print("\n--- SIMPLE ATTACK DETECTION ---")

# Rule 1: DDoS Detection (174-byte TCP packets targeting the web server 172.17.0.2)
ddos_packets = df[(df['Length'] == 174) & (df['Destination'] == '172.17.0.2')]
print(f"Detected DDoS SYN Flood packets: {len(ddos_packets):,} ({len(ddos_packets)/len(df)*100:.2f}% of all traffic)")

# Rule 2: Port Sweep / Closed Port Detection (ICMP Port Unreachable or RST responses)
port_scan_resets = df[df['Protocol'] == 'ICMP']
print(f"Detected Port Sweep ICMP Errors: {len(port_scan_resets):,} packets")

print("\nAnalysis Complete! Beginner script ran successfully.")
