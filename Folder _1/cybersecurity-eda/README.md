# Exploratory Data Analysis: Cyber Attack Evaluation Dataset for Deep Packet Inspection and Analysis

## Project Overview

This repository provides a systematic, research-grade Exploratory Data Analysis (EDA) and network forensic investigation of the **Cyber Attack Evaluation Dataset for Deep Packet Inspection and Analysis**, published on Mendeley Data.

- **Authoritative Source:** Mendeley Data
- **Dataset DOI:** [10.17632/3szjvt3w78.1](https://doi.org/10.17632/3szjvt3w78.1)
- **Dataset URL:** [https://data.mendeley.com/datasets/3szjvt3w78/1](https://data.mendeley.com/datasets/3szjvt3w78/1)
- **Authors:** Shishir Kumar Shandilya, Chirag Ganguli, Ivan Izonin, Atulya Nagar
- **Published Date:** October 18, 2022
- **Dataset Version:** 1
- **License:** Creative Commons Attribution 4.0 International (CC BY 4.0)

## Research Context & Objectives

The primary research objective is to establish an empirical and forensic foundation for downstream research in:
> **Adaptive Cyberattack Detection Using Machine Learning and Concept Drift Detection**

This analysis conducts an in-depth empirical audit across 16 core dimensions:
1. Dataset inventory, provenance, and integrity validation.
2. PCAPNG packet dissection and protocol forensic analysis.
3. SQL database dump inspection, schema recreation, and relational mapping.
4. Comprehensive data quality assessment (missingness, duplicates, protocol sanity, anomalies).
5. Descriptive statistical analysis (moments, quartiles, skewness, kurtosis, IQR).
6. Temporal traffic analysis (bursts, packet/byte rates, inter-arrival times, connection dynamics).
7. Cyberattack scenario investigation (DDoS, Port Scanning, SQLi, Brute Force, SSH/FTP exploits, Spoofing).
8. Univariate distribution profiling.
9. Bivariate and multivariate correlation analysis.
10. Outlier and extreme anomaly characterization.
11. Data leakage and evaluation bias assessment (identifier leakage, temporal leakage, class imbalance).
12. Preliminary data and feature drift investigation (KS-test, PSI, Jensen-Shannon divergence).
13. Academic suitability evaluation for machine learning and adaptive IDS architectures.
14. Publication-grade visualization suite.
15. Comprehensive research report (`results/reports/EDA_REPORT.md`).
16. Google Docs document integration.

## Repository Structure

```text
cybersecurity-eda/
│
├── data/
│   └── original/                   # Original archive, PCAPNG, and SQL dump (unmodified)
│
├── notebooks/
│   └── cybersecurity_eda.ipynb     # Reproducible research notebook
│
├── src/
│   ├── extract_pcap.py             # PCAPNG dissection & feature extraction engine
│   ├── analyze_sql.py              # SQL schema parser & SQLite relational mapper
│   ├── data_quality.py             # Data quality audit & verification pipeline
│   ├── statistical_analysis.py     # Parametric & non-parametric statistical profiler
│   ├── network_analysis.py         # Cybersecurity domain & attack pattern analyzer
│   ├── temporal_analysis.py        # Time-series, rate, and burst dynamics
│   ├── drift_analysis.py           # Windowed feature drift & statistical distance tests
│   └── visualization.py            # Publication-grade plotting module
│
├── results/
│   ├── figures/                    # High-resolution analytical figures (PNG/PDF)
│   ├── tables/                     # Statistical & data quality tables (CSV/Markdown)
│   ├── extracted_data/             # Parsed packet flows and structured CSV data
│   └── reports/
│       └── EDA_REPORT.md           # Exhaustive academic-grade EDA research report
│
├── requirements.txt                # Pinned dependency manifest
└── README.md                       # Project documentation
```

## Setup & Reproduction

1. **Environment Setup:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Run Pipeline:**
   Execute scripts in sequence or explore through `notebooks/cybersecurity_eda.ipynb`.
