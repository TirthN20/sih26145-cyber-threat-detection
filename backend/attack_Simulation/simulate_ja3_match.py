"""
SIMULATE A JA3 MALICIOUS FINGERPRINT MATCH
====================================================
Sends HTTPS connections whose TLS "handshake fingerprint" (JA3 hash)
matches a known-malicious signature already in your threat feed
(ja3_threat_feed.json) — this is the layer that catches malware
without ever decrypting or inspecting a single byte of the actual
traffic content, purely from how the connection introduces itself.

Requires the backend to already be running:
    uvicorn main_mysql:app --reload

Usage:
    python simulate_ja3_match.py
"""

import requests
import time

API = "http://127.0.0.1:8000/api/ingest"
NEW_ATTACKER_IP = "203.0.113.64"    # change this if you re-run more than once
START_TIME = 6000.0

# a real hash from ja3_threat_feed.json — "Cobalt Strike (default malleable C2 profile)"
BAD_JA3_HASH = "e7d705a3286e19ea42f587b344ee6865"

print(f"Simulating a malicious JA3 fingerprint match from {NEW_ATTACKER_IP} ...")
fired = False
t = START_TIME
for i in range(6):
    t += 20.0  # a beacon-ish check-in interval, though even 1 packet is enough to match
    r = requests.post(API, json={
        "timestamp": t, "src_ip": NEW_ATTACKER_IP, "dst_ip": "172.16.0.10",
        "dst_port": 443, "protocol": "TCP", "packet_size": 480,
        "ja3": BAD_JA3_HASH,
    })
    result = r.json()
    if result["new_alerts"] and not fired:
        fired = True
        print(f"\nALERT FIRED at connection #{i+1}:")
        for a in result["new_alerts"]:
            print(f"  category: {a['category']}")
            print(f"  confidence: {a['confidence_percent']}%")
            print(f"  explanation: {a['explanation']}")
    time.sleep(0.05)

if not fired:
    print("No alert fired — is the backend running, and does ja3_threat_feed.json still have this hash?")
else:
    print("\nDone. Refresh your dashboard now — this new attacker should show up as flagged.")
