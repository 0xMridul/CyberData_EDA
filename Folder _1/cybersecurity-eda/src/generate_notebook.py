"""
Jupyter Notebook Generator for Cybersecurity EDA
"""

import nbformat as nbf
import os

nb = nbf.v4.new_notebook()
nb.metadata = {
    "kernelspec": {
        "display_name": "Python 3 (ipykernel)",
        "language": "python",
        "name": "python3"
    },
    "language_info": {
        "name": "python",
        "version": "3.12.13"
    }
}

cells = []

# Title & Metadata
cells.append(nbf.v4.new_markdown_cell("""# Exploratory Data Analysis: Cyber Attack Evaluation Dataset for Deep Packet Inspection and Analysis

**Author:** Senior Cybersecurity Data Scientist & Machine Learning Researcher  
**Dataset:** Cyber Attack Evaluation Dataset for Deep Packet Inspection and Analysis  
**Publisher:** Mendeley Data (Version 1, October 18, 2022)  
**DOI:** [10.17632/3szjvt3w78.1](https://doi.org/10.17632/3szjvt3w78.1)  
**Official URL:** [https://data.mendeley.com/datasets/3szjvt3w78/1](https://data.mendeley.com/datasets/3szjvt3w78/1)  
**Authors:** Shishir Kumar Shandilya, Chirag Ganguli, Ivan Izonin, Atulya Nagar  

---

## Executive Research Objective
This notebook executes a systematic, research-grade forensic and exploratory data analysis of the raw PCAPNG network capture (3,962,784 packets) and companion SQL/CSV representations. It assesses data quality, descriptive statistics, attack scenarios, temporal dynamics, feature drift, and academic suitability for downstream research in:
> **Adaptive Cyberattack Detection Using Machine Learning and Concept Drift Detection**
"""))

# Cell 1: Setup & Environment
cells.append(nbf.v4.new_markdown_cell("""### 1. Setup & Environment Initialization"""))
cells.append(nbf.v4.new_code_cell("""import os
import sys
import json
import sqlite3
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Add src to system path
base_dir = os.path.dirname(os.path.abspath('')) if '__file__' in locals() else os.path.abspath('..')
src_dir = os.path.join(base_dir, 'src')
if src_dir not in sys.path:
    sys.path.append(src_dir)

import extract_pcap
import analyze_sql
import data_quality
import statistical_analysis
import network_analysis
import temporal_analysis
import drift_analysis

print(f"Base Directory: {base_dir}")
print(f"Pandas: {pd.__version__} | NumPy: {np.__version__}")
"""))

# Cell 2: Phase 1 & 2 - PCAPNG Extraction & Integrity
cells.append(nbf.v4.new_markdown_cell("""### 2. Phase 1 & 2: PCAPNG Extraction and Concordance Verification"""))
cells.append(nbf.v4.new_code_cell("""pcap_path = os.path.join(base_dir, 'data', 'original', 'Cap_1_10VM_1Apache', 'L1_Cap_10PC_1S.pcapng')
csv_path = os.path.join(base_dir, 'data', 'original', 'Cap_1_10VM_1Apache', 'L1_Cap_202209051617.csv')

pcap_meta = extract_pcap.parse_pcapng_metadata(pcap_path)
print(f"PCAPNG File: {pcap_meta['file_name']}, Size: {pcap_meta['file_size_mb']} MB")

# Fast concordance check across first 5,000 frames
align_res = extract_pcap.verify_pcap_csv_alignment(pcap_path, csv_path, num_check=5000)
print(f"Alignment Verification (5,000 frames): {align_res['concordance_rate']*100:.2f}% Concordance")

# Load extracted forensic sample
sample_df = pd.read_csv(os.path.join(base_dir, 'results', 'extracted_data', 'pcap_forensic_sample_5k.csv'))
sample_df.head(5)
"""))

# Cell 3: Phase 3 - Relational SQL Database
cells.append(nbf.v4.new_markdown_cell("""### 3. Phase 3: Relational SQL Database Schema & Query Execution"""))
cells.append(nbf.v4.new_code_cell("""sqlite_path = os.path.join(base_dir, 'results', 'extracted_data', 'pcdataset.sqlite')
conn = sqlite3.connect(sqlite_path)

sql_query = \"\"\"
SELECT protocol, COUNT(*) as packet_count, 
       ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM l1_cap), 4) as percentage,
       ROUND(AVG(length), 2) as avg_packet_length,
       ROUND(AVG(time_to_live), 2) as avg_ttl
FROM l1_cap
GROUP BY protocol
ORDER BY packet_count DESC;
\"\"\"
df_sql_protos = pd.read_sql_query(sql_query, conn)
conn.close()
df_sql_protos
"""))

# Cell 4: Phase 4 - Data Quality Assessment
cells.append(nbf.v4.new_markdown_cell("""### 4. Phase 4: Data Quality Audit Report"""))
cells.append(nbf.v4.new_code_cell("""df_quality = pd.read_csv(os.path.join(base_dir, 'results', 'tables', 'data_quality_report.csv'))
print("Complete Dataset Quality Audit across 3,962,784 records:")
df_quality
"""))

# Cell 5: Phase 5 - Descriptive Statistical Analysis
cells.append(nbf.v4.new_markdown_cell("""### 5. Phase 5: Descriptive Statistical Moments & Categorical Profiling"""))
cells.append(nbf.v4.new_code_cell("""df_stats = pd.read_csv(os.path.join(base_dir, 'results', 'tables', 'descriptive_statistics.csv'))
print("Numerical Statistical Moments (Moments, Quartiles, Skewness, Kurtosis):")
df_stats
"""))

# Cell 6: Phase 6 - Temporal Network Analysis
cells.append(nbf.v4.new_markdown_cell("""### 6. Phase 6: Temporal Network Dynamics and Traffic Sessions"""))
cells.append(nbf.v4.new_code_cell("""df_clusters = pd.read_csv(os.path.join(base_dir, 'results', 'tables', 'traffic_clusters_breakdown.csv'))
print(f"Identified {len(df_clusters)} distinct behavioral traffic clusters across 23.53 hours:")
df_clusters.head(10)
"""))

# Cell 7: Phase 7 - Cybersecurity-Specific Attack Scenarios
cells.append(nbf.v4.new_markdown_cell("""### 7. Phase 7: Forensic Profile of Documented Cyberattack Scenarios"""))
cells.append(nbf.v4.new_code_cell("""df_attacks = pd.read_csv(os.path.join(base_dir, 'results', 'tables', 'attack_scenarios_summary.csv'))
df_attacks[['Attack_Category', 'Observed_Packets', 'Target', 'Attack_Rate_PPS', 'Time_Window']]
"""))

# Cell 8: Phase 12 - Preliminary Concept Drift Analysis
cells.append(nbf.v4.new_markdown_cell("""### 8. Phase 12: Preliminary Concept Drift & Statistical Distance Testing"""))
cells.append(nbf.v4.new_code_cell("""df_drift = pd.read_csv(os.path.join(base_dir, 'results', 'tables', 'drift_analysis_results.csv'))
df_profiles = pd.read_csv(os.path.join(base_dir, 'results', 'tables', 'window_feature_comparisons.csv'))

print("Operational Window Feature Profiles:")
display(df_profiles)

print("\\nStatistical Drift Metrics against W1_Baseline (KS Test, PSI, JSD):")
display(df_drift)
"""))

# Cell 9: Phase 14 - High-Resolution Visualizations Display
cells.append(nbf.v4.new_markdown_cell("""### 9. Phase 14: Research-Quality Publication Visualizations"""))
cells.append(nbf.v4.new_code_cell("""from IPython.display import Image, display

figures = [
    'fig01_protocol_distribution.png',
    'fig02_packet_length_distribution.png',
    'fig03_traffic_volume_timeseries.png',
    'fig04_ddos_flood_zoom.png',
    'fig05_top_endpoints_matrix.png',
    'fig06_port_distribution.png',
    'fig07_tcp_flag_distribution.png',
    'fig08_packet_size_by_protocol_boxplots.png',
    'fig09_correlation_heatmap.png',
    'fig10_outlier_analysis_length_ttl.png',
    'fig11_temporal_feature_drift.png',
    'fig12_attack_profiles_radar_comparison.png',
    'fig13_inter_arrival_time_distribution.png',
    'fig14_cumulative_traffic_growth.png'
]

for fig_name in figures[:4]: # Display first 4 figures inline
    fig_path = os.path.join(base_dir, 'results', 'figures', fig_name)
    print(f"Displaying {fig_name}:")
    display(Image(filename=fig_path, width=800))
"""))

# Cell 10: Research Suitability Summary
cells.append(nbf.v4.new_markdown_cell("""### 10. Research Suitability Assessment for Adaptive ML & Concept Drift

**Evaluation Conclusion:**
1. **Network Anomaly Detection & Volumetric Attack Research:** Highly suitable. The dataset provides realistic Nmap reconnaissance sweeps and an intense 13,000 PPS SYN flood attack with fine-grained microsecond timestamps.
2. **Concept Drift Research:** Partially suitable with strict experimental boundaries. While the dataset exhibits severe covariate shift (PSI > 12.0) across operational windows, this represents attack prevalence shift and synthetic tool burstiness rather than genuine gradual real-world concept drift.
3. **Supervised Multiclass ML:** Requires semi-automated or forensic heuristic labeling. The provided source labels (`Source_Known` and `Destination_Known`) indicate IP subnet membership, NOT ground-truth attack categories.
"""))

nb.cells = cells

out_nb = "cybersecurity-eda/notebooks/cybersecurity_eda.ipynb"
with open(out_nb, "w") as f:
    nbf.write(nb, f)
print(f"Successfully generated {out_nb}")
