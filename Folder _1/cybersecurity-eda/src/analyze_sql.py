"""
SQL Database Dump Inspection and Relational Database Construction Module
Author: Senior Cybersecurity Data Scientist & Network Forensics Analyst
Dataset: Cyber Attack Evaluation Dataset for Deep Packet Inspection and Analysis (DOI: 10.17632/3szjvt3w78.1)
"""

import os
import re
import sys
import time
import sqlite3
import json
from typing import Dict, Any, List
import pandas as pd


def inspect_sql_dump(sql_path: str, max_lines: int = 100) -> Dict[str, Any]:
    """
    Examines the raw MySQL dump file syntax, target table, columns, and DDL/DML structure.
    """
    if not os.path.exists(sql_path):
        raise FileNotFoundError(f"SQL file not found at {sql_path}")

    file_size_bytes = os.path.getsize(sql_path)
    file_size_mb = file_size_bytes / (1024 * 1024)

    target_table = None
    columns = []
    insert_count = 0
    sample_values = []

    with open(sql_path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= max_lines and target_table is not None:
                break
            if "INSERT INTO" in line:
                insert_count += 1
                if target_table is None:
                    # Match pattern: INSERT INTO db.table (col1, col2, ...) VALUES
                    m = re.search(r"INSERT\s+INTO\s+([^\s\(]+)\s*\((.*?)\)\s*VALUES", line, re.IGNORECASE)
                    if m:
                        target_table = m.group(1)
                        raw_cols = m.group(2)
                        columns = [c.strip().strip("`'\"") for c in raw_cols.split(",")]
                    # extract sample values
                    v_match = re.search(r"VALUES\s*\((.*?)\)", line, re.IGNORECASE)
                    if v_match:
                        sample_values.append(v_match.group(1))

    return {
        "file_path": sql_path,
        "file_name": os.path.basename(sql_path),
        "file_size_bytes": file_size_bytes,
        "file_size_mb": round(file_size_mb, 2),
        "target_table": target_table,
        "columns": columns,
        "column_count": len(columns),
        "sample_insert_row": sample_values[0] if sample_values else None,
        "ddl_present_in_dump": False, # Author's PDF confirms DDL was NOT included in dump; must be created manually
        "documented_schema": {
            "No.": "INT",
            "Time": "DECIMAL/FLOAT",
            "Source": "VARCHAR(50)",
            "Destination": "VARCHAR(50)",
            "Protocol": "VARCHAR(50)",
            "Length": "INT",
            "Time to Live": "INT",
            "Info": "VARCHAR(1024)",
            "Source_Known": "INT",
            "Destination_Known": "INT"
        }
    }


def create_sqlite_database(csv_path: str, sqlite_path: str, chunksize: int = 500000) -> Dict[str, Any]:
    """
    Constructs a relational SQLite database from the complete packet stream,
    indexing primary keys and network search dimensions for rapid SQL querying.
    """
    print(f"Building relational SQLite database at {sqlite_path}...")
    t0 = time.time()

    if os.path.exists(sqlite_path):
        os.remove(sqlite_path)

    conn = sqlite3.connect(sqlite_path)
    cur = conn.cursor()

    # Create table DDL
    cur.execute("""
    CREATE TABLE l1_cap (
        frame_no INTEGER PRIMARY KEY,
        rel_time REAL NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        protocol TEXT NOT NULL,
        length INTEGER NOT NULL,
        time_to_live INTEGER,
        info TEXT,
        source_known INTEGER NOT NULL,
        destination_known INTEGER NOT NULL
    );
    """)

    # Stream insert from CSV
    total_inserted = 0
    for chunk in pd.read_csv(csv_path, chunksize=chunksize, low_memory=False):
        # Rename columns to match schema
        chunk = chunk.rename(columns={
            "No.": "frame_no",
            "Time": "rel_time",
            "Source": "source_ip",
            "Destination": "destination_ip",
            "Protocol": "protocol",
            "Length": "length",
            "Time to Live": "time_to_live",
            "Info": "info",
            "Source_Known": "source_known",
            "Destination_Known": "destination_known"
        })
        chunk.to_sql("l1_cap", conn, if_exists="append", index=False)
        total_inserted += len(chunk)
        print(f"  Inserted {total_inserted:,} rows into SQLite...")

    # Create strategic performance indexes
    print("Creating indexes on protocol, source, destination, and relative time...")
    cur.execute("CREATE INDEX idx_l1_proto ON l1_cap(protocol);")
    cur.execute("CREATE INDEX idx_l1_src ON l1_cap(source_ip);")
    cur.execute("CREATE INDEX idx_l1_dst ON l1_cap(destination_ip);")
    cur.execute("CREATE INDEX idx_l1_time ON l1_cap(rel_time);")
    conn.commit()

    # Query verification
    cur.execute("SELECT COUNT(*) FROM l1_cap;")
    db_count = cur.fetchone()[0]

    cur.execute("SELECT protocol, COUNT(*) as cnt FROM l1_cap GROUP BY protocol ORDER BY cnt DESC LIMIT 5;")
    top_protocols = cur.fetchall()

    conn.close()
    t1 = time.time()

    db_size_mb = os.path.getsize(sqlite_path) / (1024 * 1024)

    return {
        "sqlite_path": sqlite_path,
        "total_records": db_count,
        "database_size_mb": round(db_size_mb, 2),
        "build_time_seconds": round(t1 - t0, 2),
        "top_protocols": top_protocols
    }


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sql_path = os.path.join(base_dir, "data", "original", "Cap_1_10VM_1Apache", "L1_Cap_202209051620.sql")
    csv_path = os.path.join(base_dir, "data", "original", "Cap_1_10VM_1Apache", "L1_Cap_202209051617.csv")
    output_dir = os.path.join(base_dir, "results", "extracted_data")
    sqlite_path = os.path.join(output_dir, "pcdataset.sqlite")
    os.makedirs(output_dir, exist_ok=True)

    print("=== Phase 3: SQL Database Analysis & Schema Reconstruction ===")
    dump_info = inspect_sql_dump(sql_path)
    print(f"SQL Dump: {dump_info['file_name']}, Size: {dump_info['file_size_mb']} MB")
    print(f"Target Table: {dump_info['target_table']}")
    print(f"Extracted Columns ({dump_info['column_count']}): {dump_info['columns']}")

    # Build SQLite relational database
    db_info = create_sqlite_database(csv_path, sqlite_path)
    print(f"Database built: {db_info['total_records']:,} rows in {db_info['build_time_seconds']}s")
    print(f"SQLite file size: {db_info['database_size_mb']} MB")
    print(f"Top protocols verified via SQL: {db_info['top_protocols']}")

    # Save SQL audit report
    sql_report_path = os.path.join(output_dir, "sql_analysis_summary.json")
    with open(sql_report_path, "w") as f:
        json.dump({"dump_inspection": dump_info, "sqlite_verification": db_info}, f, indent=2)
    print(f"SQL inspection report exported to {sql_report_path}")


if __name__ == "__main__":
    main()
