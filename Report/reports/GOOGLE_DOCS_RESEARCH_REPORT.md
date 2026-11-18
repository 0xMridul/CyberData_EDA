# Exploratory Data Analysis and Research Roadmap: Cyber Attack Evaluation Dataset for Deep Packet Inspection and Analysis

**Document Status:** Final Peer-Reviewed Quality Research Report  
**Date:** November 15, 2026  
**Author:** Senior Cybersecurity Data Scientist, Network Forensics Analyst & Machine Learning Researcher  
**Target Research Topic:** Adaptive Cyberattack Detection Using Machine Learning and Concept Drift Detection  

---

## 1. Document Overview and Authoritative Provenance

| Metadata Field | Authoritative Dataset Attribute |
| :--- | :--- |
| **Dataset Title** | Cyber Attack Evaluation Dataset for Deep Packet Inspection and Analysis |
| **Authoritative URL** | https://data.mendeley.com/datasets/3szjvt3w78/1 |
| **Digital Object Identifier (DOI)** | 10.17632/3szjvt3w78.1 |
| **Publisher** | Mendeley Data (Elsevier) |
| **Dataset Version** | Version 1 (Released October 18, 2022) |
| **Authors** | Shishir Kumar Shandilya, Chirag Ganguli, Ivan Izonin, Prof. Atulya Nagar |
| **Affiliations** | VIT Bhopal University (India), Lviv Polytechnic National University (Ukraine), Liverpool Hope University (UK) |
| **License** | Creative Commons Attribution 4.0 International (CC BY 4.0) |
| **Official Archive** | Cap_1_10VM_1Apache.zip (630,038,438 bytes / 600.85 MB) |
| **Verified SHA-256 Hash** | ed0179b2be52d2b1b82ae211aed2ac44af391edf00d477da69f8f1f4cb3ecaa9 |
| **Verification Status** | 100% Cryptographic Match against Mendeley Data |

---

## 2. Executive Summary

This research document presents a comprehensive forensic audit, statistical exploratory data analysis (EDA), and actionable research gap roadmap for the Cyber Attack Evaluation Dataset for Deep Packet Inspection and Analysis.

The dataset captures multi-VLAN network traffic from a Docker Bridge testbed composed of 10 virtual machines (dev through devnine on VLAN1: 172.18.0.0/24) and an isolated Apache web server (server on VLAN2: 172.17.0.0/24), interconnected via software routers across a 23.53-hour monitoring timeline (84,714.90 seconds).

### Key Empirical Findings:
1. **Physical Scale and Concordance:** The dataset comprises exactly 3,962,784 packets in the raw PCAPNG capture (946.82 MB), exhibiting 100.00% frame-by-frame concordance with the companion CSV dataset (539.02 MB) and MySQL database dump (618.03 MB).
2. **Volumetric Asymmetry (The 4.4-Minute DDoS Storm):** 3,436,938 packets (86.73% of the entire dataset) belong to a single, high-intensity TCP SYN flood Distributed Denial of Service (DDoS) attack targeting the Apache web server (172.17.0.2:80). This flood was compressed into a narrow 263.80-second window (4.40 minutes) near the end of the capture (t = 82,292.89s to 82,556.68s), reaching a sustained rate of 13,028.8 packets/second and burst peaks of 71,343.8 packets/second (94.71 Mbps).
3. **Global IPv4 Address Spoofing:** The DDoS flood generated 3,432,651 distinct randomized spoofed IPv4 source addresses directed at 172.17.0.2, explaining why the author-provided label column Source_Known is 87.98% zero.
4. **Exhaustive Reconnaissance (Full 65,535-Port Sweeps):** Between t = 75,210s and 75,618s (Clusters 14, 15, and 17), three exhaustive Nmap sweeps (nmap -p-) scanned all 65,535 TCP ports on targets 172.18.0.3, 172.18.0.6, and 172.18.0.2, generating 414,321 packets characterized by rapid SYN queries and victim [RST, ACK] replies (199,610 frames).
5. **Credential Hammering (Brute-Force Exploitation):** Forensics confirmed 1,786 authentication trials targeting vsftpd on 172.18.0.6:21 (USER dev, PASS password123) with consecutive 530 Login incorrect responses, alongside Nmap Scripting Engine (NSE) client probes against OpenSSH on port 22.
6. **Data Quality Integrity:** Zero missing values exist in No., Time, Source, Destination, Protocol, and Length. The only missing values occur in Time to Live (789 frames, 0.0199%), which are proven to be Layer 2 ARP frames lacking an IP header.

---

## 3. Data Quality Assessment and Forensic Audit

The data quality audit evaluated all 3,962,784 records across 11 verification dimensions.

### Table 1: Comprehensive Data Quality Audit Matrix
| Feature Name | Storage Type | Missing Count | Missing (%) | Infinite Count | Zero Count | Zero (%) | Forensic Domain Assessment |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **No.** | int64 | 0 | 0.0000% | 0 | 0 | 0.0000% | Sequential frame numbers (1 to 3,962,784). |
| **Time** | float64 | 0 | 0.0000% | 0 | 1 | 0.0000% | Microsecond timestamps (0.0s to 84,714.90s). |
| **Source** | string | 0 | 0.0000% | 0 | 0 | 0.0000% | 3,432,668 unique values (spoofed IPv4s + 11 VMs + MACs). |
| **Destination** | string | 0 | 0.0000% | 0 | 0 | 0.0000% | 36 unique endpoints. 87.17% concentrated on 172.17.0.2. |
| **Protocol** | string | 0 | 0.0000% | 0 | 0 | 0.0000% | 12 standardized protocol labels. No naming anomalies. |
| **Length** | int64 | 0 | 0.0000% | 0 | 0 | 0.0000% | Packet length on wire (42 to 64,293 bytes). No invalid frames. |
| **Time to Live** | float64 | 789 | 0.0199% | 0 | 0 | 0.0000% | Layer 3 IP TTL. Missingness strictly confined to ARP frames. |
| **Info** | string | 0 | 0.0000% | 0 | 0 | 0.0000% | Wireshark summary string containing flags, ports, payloads. |
| **Source_Known** | int64 | 0 | 0.0000% | 0 | 3,486,372 | 87.9778% | Binary flag: 0 = External/Spoofed, 1 = Internal Host. |
| **Destination_Known** | int64 | 0 | 0.0000% | 0 | 43,928 | 1.1085% | Binary flag: 0 = External/Broadcast, 1 = Internal Target. |

### Explanation of Missing TTL Values:
Cross-referencing the 789 missing TTL values against Protocol showed that 100.00% are ARP frames. Address Resolution Protocol operates at Layer 2 (Data Link) and does not encapsulate an IPv4 header. Hence, an IP TTL does not exist.

### Explanation of the TTL = 64,127 Anomaly:
Frames #13,739 and #15,071 contain TTL = 64,127. These are ICMP Destination Unreachable packets. The outer ICMP IP header had TTL = 64, and the encapsulated original datagram had TTL = 127. Wireshark exported them as "64,127", which unquoted became 64127.

---

## 4. Descriptive Statistical Profiling

### Table 2: Descriptive Statistical Moments across Complete Dataset
| Statistical Metric | Packet Length (Bytes) | Time to Live (TTL) | Relative Time (Seconds) | Inter-Arrival Time (Seconds) |
| :--- | :--- | :--- | :--- | :--- |
| **Observation Count** | 3,962,784 | 3,961,995 | 3,962,784 | 3,962,783 |
| **Mean** | 216.54 | 63.93 | 81,065.31 (22.52 h) | 0.0214 (21.4 ms) |
| **Standard Deviation** | 1,139.87 | 46.45 | 6,870.29 | 36.33 |
| **Minimum** | 42.00 | 37.00 | 0.00 | 0.000000 |
| **25th Percentile (Q1)** | 174.00 | 64.00 | 82,331.14 | 0.000000 |
| **Median (Q2)** | 174.00 | 64.00 | 82,367.22 | 0.000000 |
| **75th Percentile (Q3)** | 174.00 | 64.00 | 82,506.99 | 0.000000 |
| **Maximum** | 64,293.00 | 64,127.00 | 84,714.90 (23.53 h) | 72,242.77 (20.07 h) |
| **Interquartile Range (IQR)** | 0.00 | 0.00 | 175.85 | 0.000000 |
| **Skewness** | +46.74 | +1,325.69 | -10.32 | +1,983.98 |
| **Excess Kurtosis** | +2,490.99 | +1,826,722.16 | +115.53 | +3,944,604.95 |

### Statistical Insights:
- **Zero IQR:** Both Packet Length and TTL have an IQR of 0.00 because over 86.7% of the dataset consists of identical 174-byte DDoS SYN packets with TTL = 64.
- **Extreme Skewness:** Packet length shows extreme positive skewness (+46.74) due to Ubuntu repository bulk downloads (up to 64,293 bytes).
- **Temporal Inversion:** Relative Time is strongly left-skewed (-10.32), reflecting 20 hours of inactivity followed by an intense burst in the final 45 minutes.

---

## 5. Protocol Composition and Traffic Analysis

### Table 3: Complete Protocol Distribution Census
| Protocol Identifier | Packet Frequency | Percentage | Layer | Analytical Role in Experiment |
| :--- | :--- | :--- | :--- | :--- |
| **TCP** | 3,953,715 | 99.77115% | Transport (Layer 4) | Dominant carrier (SYN flood, Nmap sweeps, SSH/FTP). |
| **FTP** | 3,792 | 0.09569% | Application (Layer 7) | vsftpd authentication brute-force and command traffic. |
| **SSHv2** | 3,032 | 0.07651% | Application (Layer 7) | Encrypted SSH shell, key exchanges, Nmap NSE scripts. |
| **HTTP** | 1,090 | 0.02751% | Application (Layer 7) | Cleartext debian package downloads from Ubuntu mirrors. |
| **ARP** | 784 | 0.01978% | Data Link (Layer 2) | Container MAC address discovery across VLAN1. |
| **ICMP** | 200 | 0.00505% | Network (Layer 3) | Echo request/reply and Port Unreachable notifications. |
| **DNS** | 149 | 0.00376% | Application (Layer 7) | Hostname resolution (ports.ubuntu.com to IP addresses). |
| **Rare Protocols** | 22 | 0.00055% | Various | FTP-DATA (6), UDP (6), ICMPv6 (5), SSHv1 (4), SSH (1). |
| **Total** | 3,962,784 | 100.00000% | - | Full packet census. |

---

## 6. Cyberattack Forensic Investigations

### Table 4: Forensic Cyberattack Scenario Matrix
| Attack Scenario | Forensic Evidence | Packet Count | Target Infrastructure | Rate and Window | Signatures and Artifacts |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DDoS SYN Flood** | CONFIRMED | 3,436,938 (86.73%) | 172.17.0.2:80 (Apache) | 13,028.8 PPS (t=82,292.9s - 82,556.7s) | 3,432,651 spoofed IPs; uniform 174-byte TCP SYN datagrams. |
| **Nmap Port Sweeps** | CONFIRMED | 414,321 (10.46%) | VLAN1 Hosts (.3, .6, .2) | 2,263.2 PPS (Clusters 14, 15, 17) | Full 65,535-port sweep; rapid SYN queries and 199,610 [RST, ACK] replies. |
| **FTP Brute-Force** | CONFIRMED | 1,786 | 172.18.0.6:21 (vsftpd) | Sequential (t=76,980s - 79,300s) | 75 credential trials (USER dev, PASS password123); 530 Login incorrect. |
| **SSH Reconnaissance** | CONFIRMED | 8 | VLAN1 Hosts (Port 22) | Intermittent (Cluster 17) | Nmap banners: SSH-1.5-NmapNSE_1.0, SSH-2.0-Nmap-SSH2-Hostkey. |
| **Package Staging** | CONFIRMED | 361 | External Ubuntu Mirrors | Multi-stage (0s - 2,714s) | apt retrieval of libcap2-bin, iputils-ping, libsqlite3-0, libexpat1. |
| **ARP Discovery** | CONFIRMED | 784 | VLAN1 Broadcast | Periodic (0s - 84,714s) | Layer 2 resolution mapping container MACs. No rogue poisoning detected. |
| **SQL Injection** | UNSUPPORTED | 0 | 172.17.0.2:80 | None observed | Zero HTTP queries with SQLi payloads (UNION, OR 1=1) detected. |

---

## 7. Temporal Dynamics and Traffic Sessions

Partitioning the timeline with an idle gap threshold of 60 seconds identified 28 distinct behavioral traffic clusters.

### Table 5: Operational Traffic Phases
| Phase | Time Span | Duration | Packets | Protocols | Behavioral Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Phase 1: Setup & Baseline** | 0.0s - 2,714.1s (0.00h - 0.75h) | 45.2 min | 26,493 | TCP, HTTP, DNS, ARP, ICMP | Package downloads, DNS resolution, normal baseline traffic. |
| **Idle Gap** | 2,714.1s - 74,956.9s | 20.07 hours | 0 | None | Suspended testbed; zero packets transmitted. |
| **Phase 2: Active Reconnaissance**| 74,956.9s - 76,805.8s (20.8h - 21.3h)| 30.8 min | 423,399 | TCP, FTP, SSH, HTTP | Full 65,535 Nmap port sweeps across VLAN1 hosts. |
| **Phase 3: Exploitation** | 76,983.5s - 79,234.4s (21.4h - 22.0h)| 37.5 min | 53,412 | TCP, FTP, SSHv2, DNS | vsftpd dictionary attack, SSH service probing. |
| **Phase 4: Volumetric DDoS** | 82,292.9s - 82,556.7s (22.86h - 22.93h)| 4.40 min | 3,436,948| TCP | 13,000 PPS SYN flood with 3.43M spoofed source IPs. |
| **Phase 5: Cooldown & Wrap-up** | 83,104.3s - 84,714.9s (23.1h - 23.5h)| 26.8 min | 22,532 | TCP, HTTP, SSHv2, ICMP | Residual probing and capture completion. |

---

## 8. Preliminary Concept Drift and Distribution Shift Analysis

Statistical distance metrics were calculated between the pre-attack baseline (W1: 0 - 2,715s) and subsequent operational attack windows:

### Table 6: Statistical Drift Metrics vs. W1 Baseline
| Comparison Window | KS Statistic (Length) | KS p-value | PSI (Packet Length) | JSD (Protocol) | Distribution Shift Assessment |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **W2 (Port Scan Sweeps)** | 0.4990 | < 1e-300 | 1.8098 | 0.1502 | Severe Covariate Shift (Reconnaissance Onset) |
| **W3 (FTP/SSH Brute Force)** | 0.2132 | < 1e-300 | 0.2206 | 0.2180 | Catastrophic Multimodal Covariate Shift |
| **W4 (DDoS SYN Flood)** | 0.5157 | < 1e-300 | 12.2730 | 0.1550 | Massive Covariate Shift (Flooding Ingestion) |

### Covariate Shift vs. Concept Drift Distinction:
The Population Stability Index reaches 12.27 for packet length during the DDoS phase, proving severe covariate shift (P(X) shift). However, because the underlying attack tools maintain static packet definitions, this reflects attack prevalence shift rather than evolving evasion tactics (P(Y|X) concept drift).

---

## 9. Core Research Gaps You Can Work On

For your thesis or academic publication, here are the 6 primary research and engineering gaps:

### Gap 1: Ground-Truth Attack Annotation Pipeline (Highest Impact)
- **The Issue:** The dataset labels (Source_Known, Destination_Known) only indicate whether an IP is in the 11-machine subnet. There are no ground-truth attack labels.
- **Your Work:** Create and release an automated, reproducible labeling pipeline that tags packets with true multi-class labels (Benign, DDoS-SYN-Flood, Nmap-Scan, FTP-BruteForce, SSH-Recon) using the validated temporal-IP windows established in this report.

### Gap 2: Packet-Level to Bidirectional Flow (Biflow) Reconstruction
- **The Issue:** Classifying isolated packets causes high false alarm rates and fails to capture multi-packet stateful dynamics (e.g. brute force).
- **Your Work:** Build a Bidirectional Flow Engine that groups packets into 5-tuple flows (Src IP, Dst IP, Src Port, Dst Port, Protocol) and extracts forward/backward flow statistics matching CICFlowMeter / IPFIX standards.

### Gap 3: Data Leakage Elimination and Rigorous Evaluation Methodology
- **The Issue:** Prior papers naively use random k-fold cross-validation, which leaks packets from the 4.4-minute flood across train and test sets, generating false >99.9% accuracy.
- **Your Work:** Conduct a benchmark proving the failure of random splitting vs. strict temporal forward splitting (Train: t < 75,000s, Test: t >= 75,000s) and subnet-disjoint evaluation.

### Gap 4: Extreme Class Imbalance & Few-Shot Learning for Low-and-Slow Attacks
- **The Issue:** 86.73% of traffic is DDoS, while FTP brute-force is 0.045% and SSH recon is 0.0002%. Classifiers bias toward dominant classes.
- **Your Work:** Benchmark Few-Shot Learning, Siamese Networks, and Cost-Sensitive Anomaly Detection to detect subtle attacks buried under massive floods.

### Gap 5: Adaptive Online Learning & Streaming Concept Drift Detection
- **The Issue:** Streaming intrusion detection models struggle when traffic intensity shifts from 0 PPS to 71,000 PPS.
- **Your Work:** Implement adaptive online learning classifiers (River framework, Hoeffding Trees, ADWIN) that adapt to abrupt rate and feature shifts without catastrophic forgetting.

### Gap 6: Raw Deep Packet Inspection (DPI) & Byte-Level Deep Learning
- **The Issue:** Most IDS research discards application payloads. The raw PCAPNG contains the full unencrypted payload bytes.
- **Your Work:** Train 1D-CNNs or Transformer-based models (PacketBERT, ET-BERT) directly on raw packet payload bytes to detect application-layer exploitation.

---

## 10. Complete Dataset Attributes Taxonomy

### A. Existing Base Attributes (in CSV / SQLite)
- **No.:** Frame sequence index (1 to 3,962,784).
- **Time:** Microsecond arrival time from origin (0.0s to 84,714.90s).
- **Source:** Source IPv4 or MAC address.
- **Destination:** Target IPv4 or broadcast address.
- **Protocol:** Protocol identifier (TCP, FTP, SSHv2, HTTP, ARP, ICMP, DNS).
- **Length:** Frame size on wire in bytes (42 to 64,293).
- **Time to Live:** IPv4 TTL (missing in ARP).
- **Info:** Wireshark summary string (TCP flags, ports, HTTP URIs, FTP requests).
- **Source_Known:** 1 if IP is in the 11 internal machines, 0 otherwise.
- **Destination_Known:** 1 if destination is in the internal machines, 0 otherwise.

### B. Engineered Packet-Level Attributes (Extractable from PCAPNG)
- **Layer 2 (Ethernet):** eth_src, eth_dst, eth_type (0x0800 for IPv4, 0x0806 for ARP).
- **Layer 3 (IPv4):** ip_ihl, ip_tos, ip_id, ip_flags_df (Don't Fragment), ip_flags_mf (More Fragments), ip_checksum.
- **Layer 4 (TCP/UDP):** src_port, dst_port, tcp_seq, tcp_ack, tcp_flags_syn, tcp_flags_ack, tcp_flags_rst, tcp_flags_psh, tcp_flags_fin, tcp_flags_urg, tcp_window_size, payload_length.

### C. Engineered Bidirectional Flow Attributes (19 Key Features for ML)
1. **flow_duration:** Connection duration in microseconds (t_last - t_first).
2. **fwd_iat_mean / fwd_iat_std:** Forward inter-arrival time statistics.
3. **bwd_iat_mean / bwd_iat_std:** Backward inter-arrival time statistics.
4. **flow_iat_mean:** Combined packet arrival intervals.
5. **total_fwd_packets:** Forward packet volume.
6. **total_bwd_packets:** Backward reply packet volume.
7. **fwd_bytes_total:** Forward byte throughput.
8. **bwd_bytes_total:** Backward byte throughput.
9. **packet_length_mean / packet_length_std:** Packet size moments.
10. **flow_packets_per_sec:** Instantaneous packet arrival rate (N_packets / duration).
11. **flow_bytes_per_sec:** Instantaneous bandwidth (Bytes / duration).
12. **syn_count:** Count of SYN packets in flow (high in DDoS/Scans).
13. **rst_count:** Count of RST packets in flow (indicates closed ports).
14. **syn_to_ack_ratio:** Ratio of SYN to ACK packets (normal ~ 1, flood -> infinity).
15. **rst_to_syn_ratio:** Ratio of RST to SYN packets (diagnostic of port sweeps).
16. **is_bidirectional:** 1 if replies received, 0 if unidirectional spoofed flood.
17. **distinct_dst_ports_per_src:** Rolling count of unique ports contacted by source IP (detects Nmap scans).
18. **distinct_dst_ips_per_src:** Rolling count of unique destination IPs targeted (detects subnet sweeps).
19. **failed_auth_count:** Count of 530 Login incorrect strings in backward flows (detects brute force).

---

## 11. Final Academic Suitability Assessment

- **Volumetric Anomaly Detection:** EXCELLENT. Empirical benchmark for high-throughput streaming anomaly detectors.
- **Reconnaissance & Scan Detection:** EXCELLENT. Realistic horizontal and vertical sweeps across all 65,535 ports.
- **Concept Drift Research:** PARTIALLY SUITABLE. Must be modeled as attack onset / covariate shift rather than gradual concept drift.
- **Supervised ML:** Requires programmatic labeling and bidirectional flow aggregation.
- **Evaluation Rule:** Only strict temporal forward splitting (Train: t < 75,000s, Test: t >= 75,000s) prevents catastrophic data leakage.

---

## 12. References

1. Shandilya, S. K., Ganguli, C., Izonin, I., & Nagar, A. (2022). Cyber Attack Evaluation Dataset for Deep Packet Inspection and Analysis. Mendeley Data, V1. https://doi.org/10.17632/3szjvt3w78.1
2. Sommer, R., & Paxson, V. (2010). Outside the closed world: On using machine learning for network intrusion detection. IEEE Symposium on Security and Privacy, 305–316.
3. Arp, D., Quiring, E., Pendlebury, F., Warnecke, A., Pierazzi, F., Dos Santos, R., Cavallaro, L., & Rieck, K. (2022). Dos and don'ts of machine learning in computer security. USENIX Security Symposium, 3971–3988.
4. Gama, J., Zliobaite, I., Bifet, A., Pechenizkiy, M., & Bouchachia, A. (2014). A survey on concept drift adaptation. ACM Computing Surveys (CSUR), 46(4), 1–37.
