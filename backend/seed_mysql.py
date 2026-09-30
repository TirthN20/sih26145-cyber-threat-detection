"""
SEED THE MYSQL DATABASE
====================================================
Loads traffic_log.csv into MySQL and runs the AI detection path
(ml_detection.py — Random Forest + Isolation Forest) against every
host, so every alert in the database, from the very first run, comes
from a trained model's decision — matching the actual "AI-Based
Detection" problem statement, not a rule-based fallback.

Requires:
    1. A running MySQL/MariaDB server with the database created
       (see README.md "MySQL backend" section for exact commands).
    2. Trained models already saved — run these two first if you
       haven't:
           python3 ml_training_data.py
           python3 train_models.py

Usage (from inside the backend/ folder):
    python3 seed_mysql.py
"""

import json
import os
import time
import pandas as pd

import database_mysql as db
import ml_detection as mld

# Looks in a few likely spots, so it works whether traffic_log.csv sits
# directly next to backend/, or inside a "frontend" folder next to it.

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
    print("Initializing MySQL schema...")
    db.init_db()
    db.clear_all()
    conn = db.get_conn()

    print(f"Loading {TRAFFIC_CSV} ...")
    try:
        traffic = pd.read_csv(TRAFFIC_CSV)
    except FileNotFoundError:
        print(f"ERROR: couldn't find {TRAFFIC_CSV}.")
        print("Run generate_traffic.py in the main project folder first.")
        conn.close()
        return
    traffic["dns_query"] = traffic["dns_query"].fillna("")
    traffic["ja3"] = traffic["ja3"].fillna("")

    print(f"Loading {JA3_FEED_JSON} ...")
    with open(JA3_FEED_JSON) as f:
        feed_entries = json.load(f)
    ja3_feed = {}
    with conn.cursor() as cur:
        for entry in feed_entries:
            cur.execute(
                "INSERT INTO ja3_feed (ja3, threat) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE threat=VALUES(threat)",
                (entry["ja3"], entry["threat"]),
            )
            ja3_feed[entry["ja3"]] = entry["threat"]
    conn.commit()

    print(f"Inserting {len(traffic)} packets into MySQL...")
    rows = list(traffic[["timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
                          "packet_size", "dns_query", "ja3"]].itertuples(index=False, name=None))
    with conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO traffic (timestamp, src_ip, dst_ip, dst_port, protocol, packet_size, dns_query, ja3) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", rows,
        )
    conn.commit()

    models_ready = os.path.exists(os.path.join("models", "random_forest.joblib"))
    if not models_ready:
        print("\nERROR: no trained models found in backend/models/")
        print("This project now detects threats using AI models only — run these")
        print("two commands first, then run this seed script again:")
        print("  python3 ml_training_data.py")
        print("  python3 train_models.py")
        conn.close()
        return

    first_seen = traffic.groupby("src_ip")["timestamp"].min().to_dict()

    print("Running AI detection (Random Forest + Isolation Forest) across every host...")
    total_alerts = 0
    with conn.cursor() as cur:
        for src_ip, host_df in traffic.groupby("src_ip"):
            last_t = float(host_df["timestamp"].max())
            alerts = mld.detect_via_ml(host_df, src_ip, ja3_feed, now=last_t)
            for a in alerts:
                latency = max(0.0, a["timestamp"] - first_seen.get(src_ip, a["timestamp"]))
                alert_created_at = time.time()
                cur.execute(
                    "INSERT INTO alerts (timestamp, layer, category, src_ip, confidence_percent, "
                    "explanation, detection_latency_sec, decoded_bits, ja3, matched_threat, model_used, created_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (a["timestamp"], a["layer"], a["category"], src_ip, a["confidence_percent"],
                     a["explanation"], round(latency, 2), a.get("decoded_bits", ""),
                     a.get("ja3", ""), a.get("matched_threat", ""), a["model_used"], alert_created_at),
                )
                for op in a.get("model_opinions", []):
                    cur.execute(
                        "INSERT INTO ml_predictions (src_ip, model_name, predicted_label, confidence, "
                        "is_final_verdict, features_json, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        (src_ip, op["model"], op["predicted_label"],
                         op["confidence"] if op["confidence"] is not None else -1,
                         op.get("is_final_verdict", False), "", alert_created_at),
                    )
                total_alerts += 1
    conn.commit()
    conn.close()

    print(f"\nDone. Seeded {len(traffic)} packets, {total_alerts} AI-detected alerts.")
    print("Start the API with:  uvicorn main_mysql:app --reload")
    print("Then open:           http://localhost:8000/docs")


if __name__ == "__main__":
    main()
