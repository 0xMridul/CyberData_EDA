"""
Preliminary Concept Drift & Temporal Distribution Shift Analysis Module
Author: Senior Cybersecurity Data Scientist & Network Forensics Analyst
Dataset: Cyber Attack Evaluation Dataset for Deep Packet Inspection and Analysis (DOI: 10.17632/3szjvt3w78.1)
"""

import os
import sys
import time
import json
from typing import Dict, Any, List, Tuple
import pandas as pd
import numpy as np
from scipy import stats
from scipy.spatial.distance import jensenshannon


def calculate_psi(expected: np.ndarray, actual: np.ndarray, num_buckets: int = 10) -> float:
    """
    Calculates the Population Stability Index (PSI) between a baseline (expected)
    and evaluation (actual) numerical feature distribution.
    PSI < 0.1: No significant change
    0.1 <= PSI < 0.2: Moderate drift
    PSI >= 0.2: Significant distributional shift
    """
    # Define quantile buckets on expected
    percentiles = np.linspace(0, 100, num_buckets + 1)
    bucket_bounds = np.percentile(expected, percentiles)
    bucket_bounds[0] = -np.inf
    bucket_bounds[-1] = np.inf

    # Ensure unique monotonic bounds
    bucket_bounds = np.unique(bucket_bounds)
    if len(bucket_bounds) <= 2:
        return 0.0

    expected_counts, _ = np.histogram(expected, bins=bucket_bounds)
    actual_counts, _ = np.histogram(actual, bins=bucket_bounds)

    # Convert to proportions with Laplace smoothing
    eps = 1e-4
    e_pct = (expected_counts + eps) / (len(expected) + eps * len(expected_counts))
    a_pct = (actual_counts + eps) / (len(actual) + eps * len(actual_counts))

    psi_val = np.sum((a_pct - e_pct) * np.log(a_pct / e_pct))
    return float(psi_val)


def calculate_jsd(p_counts: Dict[str, int], q_counts: Dict[str, int]) -> float:
    """
    Calculates the Jensen-Shannon Divergence (JSD) between two categorical probability distributions.
    0 <= JSD <= 1 (using log base 2).
    """
    all_keys = sorted(list(set(p_counts.keys()).union(set(q_counts.keys()))))
    total_p = sum(p_counts.values()) or 1
    total_q = sum(q_counts.values()) or 1

    p_dist = np.array([p_counts.get(k, 0) / total_p for k in all_keys], dtype=float)
    q_dist = np.array([q_counts.get(k, 0) / total_q for k in all_keys], dtype=float)

    # Replace zero with tiny epsilon for smoothing
    eps = 1e-6
    p_dist = (p_dist + eps) / np.sum(p_dist + eps)
    q_dist = (q_dist + eps) / np.sum(q_dist + eps)

    jsd = jensenshannon(p_dist, q_dist, base=2)
    return float(jsd)


def run_windowed_drift_analysis(csv_path: str) -> Dict[str, Any]:
    """
    Partitions the 23.5-hour dataset into four scientifically grounded operational windows:
    Window 1 (W1): Baseline / Staging Phase (t in [0s, 2715s]) - Legitimate traffic, setup, deb downloads
    Window 2 (W2): Nmap Full Port Scanning Phase (t in [75200s, 75620s]) - High-rate port scanning sweep
    Window 3 (W3): Service Exploitation / Brute-Force Phase (t in [76980s, 79300s]) - FTP/SSH credential attacks
    Window 4 (W4): Distributed Denial of Service (DDoS) Storm Phase (t in [82290s, 82560s]) - Massive SYN flood
    """
    print("Executing windowed distribution drift analysis...")
    t0 = time.time()

    windows = {
        "W1_Baseline": {"t_min": 0, "t_max": 2715, "lengths": [], "ttls": [], "protocols": {}},
        "W2_PortScan": {"t_min": 75200, "t_max": 75620, "lengths": [], "ttls": [], "protocols": {}},
        "W3_BruteForce": {"t_min": 76980, "t_max": 79300, "lengths": [], "ttls": [], "protocols": {}},
        "W4_DDoSFlood": {"t_min": 82290, "t_max": 82560, "lengths": [], "ttls": [], "protocols": {}}
    }

    # Stream through dataset to populate window vectors
    for chunk in pd.read_csv(csv_path, usecols=["Time", "Length", "Time to Live", "Protocol"], chunksize=500000, low_memory=False):
        for w_name, w_info in windows.items():
            mask = (chunk["Time"] >= w_info["t_min"]) & (chunk["Time"] <= w_info["t_max"])
            if mask.sum() > 0:
                sub = chunk[mask]
                w_info["lengths"].extend(sub["Length"].tolist())
                w_info["ttls"].extend(sub["Time to Live"].dropna().tolist())
                p_counts = sub["Protocol"].value_counts().to_dict()
                for k, v in p_counts.items():
                    w_info["protocols"][k] = w_info["protocols"].get(k, 0) + v

    # Convert to numpy arrays
    for w_name, w_info in windows.items():
        w_info["lengths"] = np.array(w_info["lengths"])
        w_info["ttls"] = np.array(w_info["ttls"])

    # Compute comparative drift metrics against W1_Baseline
    drift_comparisons = []
    base_len = windows["W1_Baseline"]["lengths"]
    base_ttl = windows["W1_Baseline"]["ttls"]
    base_proto = windows["W1_Baseline"]["protocols"]

    eval_windows = ["W2_PortScan", "W3_BruteForce", "W4_DDoSFlood"]

    for ew in eval_windows:
        cur_len = windows[ew]["lengths"]
        cur_ttl = windows[ew]["ttls"]
        cur_proto = windows[ew]["protocols"]

        # KS Tests
        ks_len_stat, ks_len_pval = stats.ks_2samp(base_len, cur_len)
        ks_ttl_stat, ks_ttl_pval = stats.ks_2samp(base_ttl, cur_ttl)

        # PSI
        psi_len = calculate_psi(base_len, cur_len)
        psi_ttl = calculate_psi(base_ttl, cur_ttl)

        # JSD on Protocol
        jsd_proto = calculate_jsd(base_proto, cur_proto)

        drift_comparisons.append({
            "Baseline_Window": "W1_Baseline",
            "Comparison_Window": ew,
            "KS_Length_Statistic": round(float(ks_len_stat), 4),
            "KS_Length_PValue": float(f"{ks_len_pval:.4e}"),
            "PSI_Length": round(psi_len, 4),
            "PSI_Length_Category": "Significant Drift (PSI >= 0.2)" if psi_len >= 0.2 else ("Moderate Drift" if psi_len >= 0.1 else "Stable"),
            "KS_TTL_Statistic": round(float(ks_ttl_stat), 4),
            "PSI_TTL": round(psi_ttl, 4),
            "JSD_Protocol": round(jsd_proto, 4),
            "Distribution_Shift_Assessment": "Catastrophic Covariate Shift (Attack Onset)" if psi_len >= 0.2 and jsd_proto >= 0.2 else "Moderate Feature Drift"
        })

    # Window profiles summary table
    window_profiles = []
    for w_name, w_info in windows.items():
        window_profiles.append({
            "Window": w_name,
            "Packet_Count": len(w_info["lengths"]),
            "Time_Span_Sec": f"{w_info['t_min']} - {w_info['t_max']}",
            "Mean_Length": round(float(np.mean(w_info["lengths"])), 2) if len(w_info["lengths"]) > 0 else 0,
            "Median_Length": round(float(np.median(w_info["lengths"])), 2) if len(w_info["lengths"]) > 0 else 0,
            "Mean_TTL": round(float(np.mean(w_info["ttls"])), 2) if len(w_info["ttls"]) > 0 else 0,
            "Dominant_Protocol": max(w_info["protocols"], key=w_info["protocols"].get) if w_info["protocols"] else "None",
            "Dominant_Proto_Pct": round((max(w_info["protocols"].values()) / len(w_info["lengths"])) * 100, 2) if w_info["protocols"] else 0
        })

    t1 = time.time()
    print(f"Drift analysis completed in {t1 - t0:.2f}s.")

    return {
        "drift_table": pd.DataFrame(drift_comparisons),
        "profiles_table": pd.DataFrame(window_profiles),
        "elapsed_seconds": round(t1 - t0, 2)
    }


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    csv_path = os.path.join(base_dir, "data", "original", "Cap_1_10VM_1Apache", "L1_Cap_202209051617.csv")
    tables_dir = os.path.join(base_dir, "results", "tables")
    os.makedirs(tables_dir, exist_ok=True)

    print("=== Phase 12: Preliminary Concept Drift & Distribution Shift Analysis ===")
    res = run_windowed_drift_analysis(csv_path)

    out_drift_csv = os.path.join(tables_dir, "drift_analysis_results.csv")
    res["drift_table"].to_csv(out_drift_csv, index=False)
    print(f"Saved drift analysis results to {out_drift_csv}")

    out_prof_csv = os.path.join(tables_dir, "window_feature_comparisons.csv")
    res["profiles_table"].to_csv(out_prof_csv, index=False)
    print(f"Saved window feature profiles to {out_prof_csv}")

    print("\nWindow Feature Profiles:")
    print(res["profiles_table"].to_string(index=False))

    print("\nDrift Metrics vs W1_Baseline:")
    print(res["drift_table"][["Comparison_Window", "KS_Length_Statistic", "PSI_Length", "JSD_Protocol", "Distribution_Shift_Assessment"]].to_string(index=False))


if __name__ == "__main__":
    main()
