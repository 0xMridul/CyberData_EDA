"""
Temporal Network Traffic & Time-Series Dynamics Module
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


def compute_temporal_aggregations(csv_path: str, bin_size_sec: int = 10, chunksize: int = 500000) -> Dict[str, Any]:
    """
    Computes time-series packet rates, byte volumes, and burst metrics across the entire 84,714.9s timeline.
    """
    print(f"Aggregating temporal traffic metrics with bin size {bin_size_sec}s...")
    t0 = time.time()

    max_time = 84720
    num_bins = int(max_time // bin_size_sec) + 1

    packet_counts = np.zeros(num_bins, dtype=np.int64)
    byte_counts = np.zeros(num_bins, dtype=np.int64)
    tcp_syn_counts = np.zeros(num_bins, dtype=np.int64)

    total_pkts = 0

    for chunk in pd.read_csv(csv_path, usecols=["Time", "Length", "Info"], chunksize=chunksize, low_memory=False):
        total_pkts += len(chunk)
        t_vals = chunk["Time"].values
        l_vals = chunk["Length"].values
        b_idx = (t_vals // bin_size_sec).astype(int)
        b_idx = np.clip(b_idx, 0, num_bins - 1)

        np.add.at(packet_counts, b_idx, 1)
        np.add.at(byte_counts, b_idx, l_vals)

        # Count SYN packets
        is_syn = chunk["Info"].str.contains(r"\[SYN\]", case=False, na=False).values
        np.add.at(tcp_syn_counts, b_idx, is_syn.astype(int))

    t1 = time.time()

    # Create time-series dataframe
    time_points = np.arange(num_bins) * bin_size_sec
    df_ts = pd.DataFrame({
        "time_sec": time_points,
        "time_hours": time_points / 3600.0,
        "packet_count": packet_counts,
        "byte_count": byte_counts,
        "pps": packet_counts / float(bin_size_sec),
        "mbps": (byte_counts * 8) / (bin_size_sec * 1024 * 1024),
        "tcp_syn_count": tcp_syn_counts
    })

    # Summary metrics
    active_mask = packet_counts > 0
    active_bins_count = int(active_mask.sum())
    idle_bins_count = num_bins - active_bins_count

    max_pps = float(df_ts["pps"].max())
    mean_pps_active = float(df_ts.loc[active_mask, "pps"].mean()) if active_bins_count > 0 else 0.0
    max_mbps = float(df_ts["mbps"].max())

    summary = {
        "bin_size_seconds": bin_size_sec,
        "total_timeline_seconds": max_time,
        "total_timeline_hours": round(max_time / 3600.0, 2),
        "total_packets": total_pkts,
        "total_bins": num_bins,
        "active_bins": active_bins_count,
        "idle_bins": idle_bins_count,
        "active_ratio_percentage": round((active_bins_count / num_bins) * 100, 2),
        "max_pps": round(max_pps, 1),
        "mean_active_pps": round(mean_pps_active, 1),
        "max_mbps": round(max_mbps, 2),
        "processing_seconds": round(t1 - t0, 2)
    }

    return {"df_timeseries": df_ts, "summary": summary}


def identify_traffic_clusters(csv_path: str, idle_gap_sec: float = 60.0, chunksize: int = 500000) -> pd.DataFrame:
    """
    Partitions the traffic into discrete behavioral sessions separated by idle intervals.
    """
    print(f"Segmenting traffic sessions with idle gap threshold {idle_gap_sec}s...")
    t0 = time.time()

    clusters = []
    cluster_start = None
    cluster_end = None
    cluster_count = 0
    cluster_bytes = 0
    cluster_protos = set()
    prev_time = -1e9

    for chunk in pd.read_csv(csv_path, usecols=["Time", "Length", "Protocol"], chunksize=chunksize, low_memory=False):
        for row in chunk.itertuples():
            t = row.Time
            if t - prev_time > idle_gap_sec:
                if cluster_count > 0:
                    dur = max(cluster_end - cluster_start, 0.001)
                    clusters.append({
                        "cluster_id": len(clusters) + 1,
                        "start_time_sec": round(cluster_start, 2),
                        "end_time_sec": round(cluster_end, 2),
                        "start_time_hr": round(cluster_start / 3600.0, 3),
                        "end_time_hr": round(cluster_end / 3600.0, 3),
                        "duration_sec": round(dur, 2),
                        "packet_count": cluster_count,
                        "byte_count": cluster_bytes,
                        "mean_pps": round(cluster_count / dur, 1),
                        "protocols": ", ".join(sorted(list(cluster_protos)))
                    })
                cluster_start = t
                cluster_end = t
                cluster_count = 1
                cluster_bytes = row.Length
                cluster_protos = {row.Protocol}
            else:
                cluster_end = t
                cluster_count += 1
                cluster_bytes += row.Length
                cluster_protos.add(row.Protocol)
            prev_time = t

    if cluster_count > 0:
        dur = max(cluster_end - cluster_start, 0.001)
        clusters.append({
            "cluster_id": len(clusters) + 1,
            "start_time_sec": round(cluster_start, 2),
            "end_time_sec": round(cluster_end, 2),
            "start_time_hr": round(cluster_start / 3600.0, 3),
            "end_time_hr": round(cluster_end / 3600.0, 3),
            "duration_sec": round(dur, 2),
            "packet_count": cluster_count,
            "byte_count": cluster_bytes,
            "mean_pps": round(cluster_count / dur, 1),
            "protocols": ", ".join(sorted(list(cluster_protos)))
        })

    t1 = time.time()
    print(f"Segmented {len(clusters)} traffic clusters in {t1 - t0:.2f}s.")
    return pd.DataFrame(clusters)


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    csv_path = os.path.join(base_dir, "data", "original", "Cap_1_10VM_1Apache", "L1_Cap_202209051617.csv")
    tables_dir = os.path.join(base_dir, "results", "tables")
    os.makedirs(tables_dir, exist_ok=True)

    print("=== Phase 6: Temporal Network Traffic Analysis ===")
    ts_res = compute_temporal_aggregations(csv_path, bin_size_sec=10)
    out_ts_csv = os.path.join(tables_dir, "temporal_traffic_timeseries_10s.csv")
    # Save active and representative bins to avoid massive 8000-row file
    ts_res["df_timeseries"].to_csv(out_ts_csv, index=False)
    print(f"Saved temporal timeseries table to {out_ts_csv}")

    out_ts_meta = os.path.join(tables_dir, "temporal_traffic_summary.json")
    with open(out_ts_meta, "w") as f:
        json.dump(ts_res["summary"], f, indent=2)
    print(f"Saved temporal summary JSON to {out_ts_meta}")

    df_clusters = identify_traffic_clusters(csv_path, idle_gap_sec=60.0)
    out_cluster_csv = os.path.join(tables_dir, "traffic_clusters_breakdown.csv")
    df_clusters.to_csv(out_cluster_csv, index=False)
    print(f"Saved traffic clusters table to {out_cluster_csv}")

    print("\nTemporal Dynamics Summary:")
    print(f"  Total timeline: {ts_res['summary']['total_timeline_hours']} hours")
    print(f"  Active time ratio: {ts_res['summary']['active_ratio_percentage']}%")
    print(f"  Peak packet rate: {ts_res['summary']['max_pps']:,} packets/sec")
    print(f"  Peak bandwidth: {ts_res['summary']['max_mbps']} Mbps")
    print(f"  Distinct traffic sessions: {len(df_clusters)}")


if __name__ == "__main__":
    main()
