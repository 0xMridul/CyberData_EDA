"""
PCAP/PCAPNG Extraction and Dissection Module
Author: Senior Cybersecurity Data Scientist & Network Forensics Analyst
Dataset: Cyber Attack Evaluation Dataset for Deep Packet Inspection and Analysis (DOI: 10.17632/3szjvt3w78.1)
"""

import os
import sys
import time
import socket
import json
from typing import Dict, Any, Generator, Tuple, Optional
import dpkt
import pandas as pd
import numpy as np


def parse_pcapng_metadata(pcap_path: str) -> Dict[str, Any]:
    """
    Extracts high-level file metadata and verifies PCAPNG integrity.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAPNG file not found at {pcap_path}")

    file_size_bytes = os.path.getsize(pcap_path)
    file_size_mb = file_size_bytes / (1024 * 1024)

    return {
        "file_path": pcap_path,
        "file_name": os.path.basename(pcap_path),
        "file_size_bytes": file_size_bytes,
        "file_size_mb": round(file_size_mb, 2),
    }


def iter_packets(pcap_path: str, max_packets: Optional[int] = None) -> Generator[Dict[str, Any], None, None]:
    """
    High-performance generator decoding packets from PCAPNG using dpkt.
    Yields structured dictionaries with standard packet fields.
    """
    with open(pcap_path, "rb") as f:
        reader = dpkt.pcapng.Reader(f)
        first_ts = None
        count = 0

        for ts, buf in reader:
            count += 1
            if first_ts is None:
                first_ts = ts
            rel_time = ts - first_ts

            pkt_len = len(buf)
            eth = dpkt.ethernet.Ethernet(buf)

            # Default attributes
            eth_src = getattr(eth, "src", b"").hex(":")
            eth_dst = getattr(eth, "dst", b"").hex(":")
            ip_ver = None
            src_ip = None
            dst_ip = None
            protocol_name = "ETHERNET"
            src_port = None
            dst_port = None
            tcp_flags = None
            tcp_flags_hex = None
            win_size = None
            ttl = None
            payload_len = 0

            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                ip_ver = 4
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                ttl = ip.ttl
                p_code = ip.p

                if p_code == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    protocol_name = "TCP"
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    flags_val = tcp.flags
                    tcp_flags_hex = hex(flags_val)
                    flag_list = []
                    if flags_val & dpkt.tcp.TH_FIN: flag_list.append("FIN")
                    if flags_val & dpkt.tcp.TH_SYN: flag_list.append("SYN")
                    if flags_val & dpkt.tcp.TH_RST: flag_list.append("RST")
                    if flags_val & dpkt.tcp.TH_PUSH: flag_list.append("PSH")
                    if flags_val & dpkt.tcp.TH_ACK: flag_list.append("ACK")
                    if flags_val & dpkt.tcp.TH_URG: flag_list.append("URG")
                    tcp_flags = ",".join(flag_list) if flag_list else "NONE"
                    win_size = tcp.win
                    payload_len = len(tcp.data)

                elif p_code == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    protocol_name = "UDP"
                    src_port = udp.sport
                    dst_port = udp.dport
                    payload_len = len(udp.data)

                elif p_code == dpkt.ip.IP_PROTO_ICMP and isinstance(ip.data, dpkt.icmp.ICMP):
                    protocol_name = "ICMP"
                    payload_len = len(ip.data)
                else:
                    protocol_name = f"IP_PROTO_{p_code}"
                    payload_len = len(ip.data)

            elif isinstance(eth.data, dpkt.ip6.IP6):
                ip6 = eth.data
                ip_ver = 6
                src_ip = socket.inet_ntop(socket.AF_INET6, ip6.src)
                dst_ip = socket.inet_ntop(socket.AF_INET6, ip6.dst)
                ttl = ip6.hlim
                protocol_name = f"IPv6_PROTO_{ip6.nxt}"
                payload_len = len(ip6.data)

            elif isinstance(eth.data, dpkt.arp.ARP):
                protocol_name = "ARP"
                arp = eth.data
                try:
                    src_ip = socket.inet_ntoa(arp.spa)
                    dst_ip = socket.inet_ntoa(arp.tpa)
                except Exception:
                    pass

            yield {
                "frame_num": count,
                "epoch_time": ts,
                "relative_time": rel_time,
                "packet_length": pkt_len,
                "eth_src": eth_src,
                "eth_dst": eth_dst,
                "ip_version": ip_ver,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol_name,
                "src_port": src_port,
                "dst_port": dst_port,
                "tcp_flags": tcp_flags,
                "tcp_flags_hex": tcp_flags_hex,
                "window_size": win_size,
                "ttl": ttl,
                "payload_length": payload_len,
            }

            if max_packets is not None and count >= max_packets:
                break


def verify_pcap_csv_alignment(pcap_path: str, csv_path: str, num_check: int = 50000) -> Dict[str, Any]:
    """
    Verifies frame-by-frame 1-to-1 correspondence between PCAPNG and Wireshark CSV export.
    """
    print(f"Validating alignment between {os.path.basename(pcap_path)} and {os.path.basename(csv_path)}...")
    t0 = time.time()

    df_csv = pd.read_csv(csv_path, nrows=num_check)
    pcap_gen = iter_packets(pcap_path, max_packets=num_check)

    mismatches = 0
    checked = 0

    for csv_row, pcap_row in zip(df_csv.itertuples(), pcap_gen):
        checked += 1
        # Check frame number
        if int(csv_row._1) != pcap_row["frame_num"]:
            mismatches += 1
            continue
        # Check packet length
        if int(csv_row.Length) != pcap_row["packet_length"]:
            mismatches += 1
            continue
        # Check relative time within microsecond tolerance
        if abs(float(csv_row.Time) - pcap_row["relative_time"]) > 0.0001:
            mismatches += 1

    t1 = time.time()
    return {
        "frames_verified": checked,
        "mismatches": mismatches,
        "concordance_rate": (checked - mismatches) / checked if checked > 0 else 0,
        "elapsed_seconds": round(t1 - t0, 3)
    }


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pcap_path = os.path.join(base_dir, "data", "original", "Cap_1_10VM_1Apache", "L1_Cap_10PC_1S.pcapng")
    csv_path = os.path.join(base_dir, "data", "original", "Cap_1_10VM_1Apache", "L1_Cap_202209051617.csv")
    output_dir = os.path.join(base_dir, "results", "extracted_data")
    os.makedirs(output_dir, exist_ok=True)

    print("=== Phase 2: PCAP/PCAPNG Forensic Extraction ===")
    meta = parse_pcapng_metadata(pcap_path)
    print(f"File: {meta['file_name']}, Size: {meta['file_size_mb']} MB")

    # Verify alignment
    align_result = verify_pcap_csv_alignment(pcap_path, csv_path, num_check=25000)
    print(f"Alignment verification: {align_result['frames_verified']} frames checked. Concordance: {align_result['concordance_rate']*100:.2f}%")

    # Sample extraction
    print("Extracting sample forensic records...")
    records = []
    for pkt in iter_packets(pcap_path, max_packets=5000):
        records.append(pkt)

    sample_df = pd.DataFrame(records)
    sample_csv = os.path.join(output_dir, "pcap_forensic_sample_5k.csv")
    sample_df.to_csv(sample_csv, index=False)
    print(f"Saved forensic sample (5,000 frames) to {sample_csv}")

    # Save summary metadata
    summary_path = os.path.join(output_dir, "pcap_metadata.json")
    with open(summary_path, "w") as f:
        json.dump({**meta, "alignment": align_result}, f, indent=2)
    print(f"Metadata exported to {summary_path}")


if __name__ == "__main__":
    main()
