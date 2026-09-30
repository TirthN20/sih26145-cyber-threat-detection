"""
STREAM TEST DATA LIVE INTO YOUR RUNNING SYSTEM
====================================================
Sends live_stream_test.csv into your backend one packet at a time
through /api/ingest — ADDS to whatever's already there (your existing
3763-packet demo data stays exactly as it is), rather than wiping and
reloading like seed_mysql.py / seed_large_test.py do.

This is built for actually watching it happen: run this, then have
your dashboard open in a browser tab — refresh it every 10-15 seconds
while this runs and you'll see "packets analyzed" and "threats
detected" climb in real time, with new alert cards appearing for each
of the 15 attackers as they get caught.

Requires the backend already running:
    uvicorn main_mysql:app --reload

Usage (from inside backend/):
    python3 run_live_stream.py
"""

import json
import os
import time
import requests
import pandas as pd

API = "http://127.0.0.1:8000"


def _find(filename):
    candidates = [os.path.join("..", filename), os.path.join("..", "frontend", filename), filename]
    for c in candidates:
        if os.path.exists(c):
            return c
    return candidates[0]


TRAFFIC_CSV = _find("live_stream_test.csv")
GROUND_TRUTH_JSON = _find("live_stream_ground_truth.json")


def main():
    if not os.path.exists(TRAFFIC_CSV):
        print(f"ERROR: couldn't find {TRAFFIC_CSV}.")
        print("Run generate_live_stream_dataset.py in the project root first.")
        return

    try:
        before = requests.get(f"{API}/api/stats", timeout=5).json()
    except requests.exceptions.RequestException:
        print(f"ERROR: can't reach the backend at {API}. Start it first:")
        print("  uvicorn main_mysql:app --reload")
        return
    print(f"Before streaming: {before['packets_analyzed']} packets, {before['threats_detected']} threats\n")

    traffic = pd.read_csv(TRAFFIC_CSV)
    traffic["dns_query"] = traffic["dns_query"].fillna("")
    traffic["ja3"] = traffic["ja3"].fillna("")

    with open(GROUND_TRUTH_JSON) as f:
        gt = json.load(f)

    print(f"Streaming {len(traffic)} packets into your running system...")
    print("(leave this running and refresh your dashboard tab every 10-15s to watch it update)\n")

    seen_categories = {}  # src_ip -> category, first time we see an alert for it
    t0 = time.time()
    for i, row in enumerate(traffic.itertuples(index=False)):
        r = requests.post(f"{API}/api/ingest", json={
            "timestamp": row.timestamp, "src_ip": row.src_ip, "dst_ip": row.dst_ip,
            "dst_port": int(row.dst_port), "protocol": row.protocol,
            "packet_size": int(row.packet_size), "dns_query": row.dns_query, "ja3": row.ja3,
        }, timeout=5)
        result = r.json()
        for a in result.get("new_alerts", []):
            if a["model_used"] == "random_forest" and row.src_ip not in seen_categories:
                seen_categories[row.src_ip] = a["category"]
                elapsed = time.time() - t0
                print(f"  [{elapsed:5.1f}s, packet {i+1}/{len(traffic)}] ALERT: {row.src_ip} -> {a['category']} "
                      f"({a['confidence_percent']}%)")

        if (i + 1) % 300 == 0:
            print(f"  ... {i+1}/{len(traffic)} packets streamed so far")

    elapsed = time.time() - t0
    after = requests.get(f"{API}/api/stats", timeout=5).json()

    print(f"\nDone in {elapsed:.1f}s.")
    print(f"After streaming: {after['packets_analyzed']} packets, {after['threats_detected']} threats "
          f"(+{after['packets_analyzed']-before['packets_analyzed']} packets, "
          f"+{after['threats_detected']-before['threats_detected']} threats)")

    total_attackers = len(gt["attackers"])
    correct = sum(1 for ip, cat in gt["attackers"].items() if seen_categories.get(ip) == cat)
    print(f"\nScorecard: {correct}/{total_attackers} attackers correctly caught by name.")
    missed = [ip for ip in gt["attackers"] if ip not in seen_categories]
    if missed:
        print(f"Not caught within this stream: {missed}")
    print("\nRefresh your dashboard now — these hosts are live alongside your existing demo data.")


if __name__ == "__main__":
    main()
