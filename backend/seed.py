"""
SEED THE DATABASE
====================================================
Run this once (or whenever you regenerate traffic_log.csv) to load the
synthetic traffic + JA3 feed into the database and run detection over
it, so the API has data to serve immediately on startup.

This is the backend's equivalent of running generate_traffic.py +
detector.py — same data, same detection logic, just going into a real
database instead of CSV files.

Usage (from inside the backend/ folder):
    python3 seed.py
"""

import json
import time
import pandas as pd

import database as db
import detection as det

# Looks in a few likely spots, so it works whether traffic_log.csv sits
# directly next to backend/, or inside a "frontend" folder next to it.
import os

def _find(filename):
    candidates = [
        os.path.join("..", filename),
        os.path.join("..", "frontend", filename),
        filename,
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return candidates[0]  # fall back to the default so the error message below still makes sense

TRAFFIC_CSV = _find("traffic_log.csv")
JA3_FEED_JSON = _find("ja3_threat_feed.json")


def main():
    print("Initializing database...")
    db.init_db()
    db.clear_all()
    conn = db.get_conn()

    print(f"Loading {TRAFFIC_CSV} ...")
    try:
        traffic = pd.read_csv(TRAFFIC_CSV)
    except FileNotFoundError:
        print(f"ERROR: couldn't find {TRAFFIC_CSV}.")
        print("Run generate_traffic.py in the main project folder first,")
        print("then come back and run this seed script again.")
        return
    traffic["dns_query"] = traffic["dns_query"].fillna("")
    traffic["ja3"] = traffic["ja3"].fillna("")

    print(f"Loading {JA3_FEED_JSON} ...")
    with open(JA3_FEED_JSON) as f:
        feed_entries = json.load(f)
    ja3_feed = {}
    for entry in feed_entries:
        conn.execute("INSERT OR REPLACE INTO ja3_feed (ja3, threat) VALUES (?, ?)",
                     (entry["ja3"], entry["threat"]))
        ja3_feed[entry["ja3"]] = entry["threat"]
    conn.commit()

    print(f"Inserting {len(traffic)} packets into the database...")
    rows = list(traffic[["timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
                          "packet_size", "dns_query", "ja3"]].itertuples(index=False, name=None))
    conn.executemany(
        "INSERT INTO traffic (timestamp, src_ip, dst_ip, dst_port, protocol, packet_size, dns_query, ja3) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows,
    )
    conn.commit()

    first_seen = traffic.groupby("src_ip")["timestamp"].min().to_dict()

    print("Running detection across every host...")
    total_alerts = 0
    for src_ip, host_df in traffic.groupby("src_ip"):
        alerts = det.run_all_checks(host_df, src_ip, ja3_feed)
        for a in alerts:
            latency = max(0.0, a["timestamp"] - first_seen.get(src_ip, a["timestamp"]))
            conn.execute(
                "INSERT INTO alerts (timestamp, layer, category, src_ip, confidence_percent, "
                "explanation, detection_latency_sec, decoded_bits, ja3, matched_threat, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (a["timestamp"], a["layer"], a["category"], a["src_ip"], a["confidence_percent"],
                 a["explanation"], round(latency, 2), a.get("decoded_bits", ""),
                 a.get("ja3", ""), a.get("matched_threat", ""), time.time()),
            )
            total_alerts += 1
    conn.commit()
    conn.close()

    print(f"\nDone. Seeded {len(traffic)} packets and {total_alerts} alerts.")
    print("Start the API with:  uvicorn main:app --reload")
    print("Then open:           http://localhost:8000/docs")


if __name__ == "__main__":
    main()
