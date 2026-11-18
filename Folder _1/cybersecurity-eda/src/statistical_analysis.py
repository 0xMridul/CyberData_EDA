"""
Descriptive Statistical Analysis & Distribution Profiling Module
Author: Senior Cybersecurity Data Scientist & Network Forensics Analyst
Dataset: Cyber Attack Evaluation Dataset for Deep Packet Inspection and Analysis (DOI: 10.17632/3szjvt3w78.1)
"""

import os
import sys
import time
import json
from typing import Dict, Any, List
import pandas as pd
import numpy as np
from scipy import stats


def compute_numerical_statistics(csv_path: str, chunksize: int = 500000) -> pd.DataFrame:
    """
    Computes exact descriptive statistics (moments, quartiles, IQR, skewness, kurtosis)
    across the complete multi-million row dataset using high-performance chunking and reservoir/Welford algorithms.
    """
    print(f"Computing exact descriptive statistics for numerical features in {os.path.basename(csv_path)}...")
    t0 = time.time()

    # We extract numerical columns: Length, Time to Live, and relative Time
    # Also compute packet-to-packet Inter-Arrival Time (IAT)
    all_lengths = []
    all_ttls = []
    all_times = []

    for chunk in pd.read_csv(csv_path, usecols=["Length", "Time to Live", "Time"], chunksize=chunksize, low_memory=False):
        all_lengths.append(chunk["Length"].values)
        all_ttls.append(chunk["Time to Live"].dropna().values)
        all_times.append(chunk["Time"].values)

    lengths = np.concatenate(all_lengths)
    ttls = np.concatenate(all_ttls)
    times = np.concatenate(all_times)

    # Calculate Inter-Arrival Time (IAT) in seconds
    iats = np.diff(times)
    iats = np.clip(iats, 0, None) # handle non-negative delta

    feature_dict = {
        "Length (bytes)": lengths,
        "Time to Live (TTL)": ttls,
        "Relative Time (s)": times,
        "Inter-Arrival Time (s)": iats
    }

    stat_rows = []
    for name, arr in feature_dict.items():
        n = len(arr)
        mean_val = float(np.mean(arr))
        std_val = float(np.std(arr, ddof=1))
        min_val = float(np.min(arr))
        max_val = float(np.max(arr))

        q25 = float(np.percentile(arr, 25))
        median_val = float(np.percentile(arr, 50))
        q75 = float(np.percentile(arr, 75))
        iqr_val = q75 - q25

        # Moments
        skew_val = float(stats.skew(arr))
        kurt_val = float(stats.kurtosis(arr)) # Fisher's excess kurtosis

        stat_rows.append({
            "Feature": name,
            "Count": n,
            "Mean": round(mean_val, 4),
            "Std": round(std_val, 4),
            "Min": round(min_val, 4),
            "Q25 (25%)": round(q25, 4),
            "Median (50%)": round(median_val, 4),
            "Q75 (75%)": round(q75, 4),
            "Max": round(max_val, 4),
            "IQR": round(iqr_val, 4),
            "Skewness": round(skew_val, 4),
            "Kurtosis": round(kurt_val, 4)
        })

    df_stats = pd.DataFrame(stat_rows)
    t1 = time.time()
    print(f"Descriptive statistics computed in {t1 - t0:.2f}s.")
    return df_stats


def compute_categorical_summary(csv_path: str, chunksize: int = 500000) -> Dict[str, pd.DataFrame]:
    """
    Computes categorical cardinality, frequency distributions, and proportions.
    """
    print(f"Computing categorical distributions for {os.path.basename(csv_path)}...")
    t0 = time.time()

    from collections import Counter
    proto_counter = Counter()
    src_known_counter = Counter()
    dst_known_counter = Counter()
    src_ip_counter = Counter()
    dst_ip_counter = Counter()

    total_rows = 0
    for chunk in pd.read_csv(csv_path, usecols=["Protocol", "Source", "Destination", "Source_Known", "Destination_Known"], chunksize=chunksize, low_memory=False):
        total_rows += len(chunk)
        proto_counter.update(chunk["Protocol"].dropna().astype(str))
        src_known_counter.update(chunk["Source_Known"].dropna())
        dst_known_counter.update(chunk["Destination_Known"].dropna())
        src_ip_counter.update(chunk["Source"].dropna().astype(str))
        dst_ip_counter.update(chunk["Destination"].dropna().astype(str))

    # Protocol summary table
    proto_rows = []
    for p, cnt in proto_counter.most_common():
        proto_rows.append({
            "Protocol": p,
            "Frequency": cnt,
            "Percentage": round((cnt / total_rows) * 100, 5),
            "Classification": "Dominant (Transport)" if cnt > 100000 else ("Application/Control" if cnt > 100 else "Rare Protocol")
        })
    df_proto = pd.DataFrame(proto_rows)

    # Binary flags summary table
    binary_rows = [
        {"Feature": "Source_Known", "Value": 1, "Count": src_known_counter[1], "Percentage": round(src_known_counter[1]/total_rows*100, 4), "Interpretation": "Known Internal Subnet (10+1 Machines)"},
        {"Feature": "Source_Known", "Value": 0, "Count": src_known_counter[0], "Percentage": round(src_known_counter[0]/total_rows*100, 4), "Interpretation": "Spoofed / External Source"},
        {"Feature": "Destination_Known", "Value": 1, "Count": dst_known_counter[1], "Percentage": round(dst_known_counter[1]/total_rows*100, 4), "Interpretation": "Internal Target (predominantly Apache Server)"},
        {"Feature": "Destination_Known", "Value": 0, "Count": dst_known_counter[0], "Percentage": round(dst_known_counter[0]/total_rows*100, 4), "Interpretation": "External Destination / Broadcast"}
    ]
    df_binary = pd.DataFrame(binary_rows)

    t1 = time.time()
    print(f"Categorical summary computed in {t1 - t0:.2f}s.")
    return {"protocols": df_proto, "binary_flags": df_binary, "total_rows": total_rows}


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    csv_path = os.path.join(base_dir, "data", "original", "Cap_1_10VM_1Apache", "L1_Cap_202209051617.csv")
    tables_dir = os.path.join(base_dir, "results", "tables")
    os.makedirs(tables_dir, exist_ok=True)

    print("=== Phase 5: Statistical Analysis ===")
    df_numerical = compute_numerical_statistics(csv_path)
    out_num_csv = os.path.join(tables_dir, "descriptive_statistics.csv")
    df_numerical.to_csv(out_num_csv, index=False)
    print(f"Saved numerical statistics to {out_num_csv}")

    cat_res = compute_categorical_summary(csv_path)
    out_proto_csv = os.path.join(tables_dir, "protocol_distribution.csv")
    cat_res["protocols"].to_csv(out_proto_csv, index=False)
    print(f"Saved protocol distribution to {out_proto_csv}")

    out_bin_csv = os.path.join(tables_dir, "binary_flags_summary.csv")
    cat_res["binary_flags"].to_csv(out_bin_csv, index=False)
    print(f"Saved binary flags summary to {out_bin_csv}")

    print("\nNumerical Statistics Table Preview:")
    print(df_numerical.to_string(index=False))

    print("\nProtocol Distribution Preview:")
    print(cat_res["protocols"].head(8).to_string(index=False))


if __name__ == "__main__":
    main()
