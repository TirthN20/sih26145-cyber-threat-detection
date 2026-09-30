"""
SIMULATE A COVERT TIMING CHANNEL
====================================================
Sends packets that look completely normal (regular size, regular
HTTPS port) — the ONLY suspicious thing is the exact GAP between each
packet, which alternates between a short value (encoding bit 0) and a
long value (encoding bit 1). This is the attack designed specifically
to defeat systems that only look at packet content, not timing.

Requires the backend to already be running:
    uvicorn main_mysql:app --reload

Usage:
    python simulate_covert_channel.py
"""

import random
import requests
import time

API = "http://127.0.0.1:8000/api/ingest"
NEW_ATTACKER_IP = "203.0.113.63"    # change this if you re-run more than once
START_TIME = 5000.0
SHORT_GAP = 0.20   # bit 0
LONG_GAP = 0.55    # bit 1 (well over the 1.8x separation the detector needs)

random.seed()
secret_bits = [random.randint(0, 1) for _ in range(45)]  # >30 needed to trigger

print(f"Simulating a covert timing channel from {NEW_ATTACKER_IP} ...")
print(f"Hidden message (first 20 bits): {''.join(map(str, secret_bits[:20]))}...")
fired = False
t = START_TIME
for i, bit in enumerate(secret_bits):
    gap = (SHORT_GAP if bit == 0 else LONG_GAP) + random.uniform(-0.01, 0.01)
    t += gap
    r = requests.post(API, json={
        "timestamp": t, "src_ip": NEW_ATTACKER_IP, "dst_ip": "172.16.0.10",
        "dst_port": 443, "protocol": "TCP", "packet_size": 500,  # normal-looking HTTPS traffic
    })
    result = r.json()
    if result["new_alerts"] and not fired:
        fired = True
        print(f"\nALERT FIRED at packet #{i+1}:")
        for a in result["new_alerts"]:
            print(f"  category: {a['category']}")
            print(f"  confidence: {a['confidence_percent']}%")
            print(f"  explanation: {a['explanation']}")
            if a.get("decoded_bits"):
                print(f"  decoded bits: {a['decoded_bits']}")
    time.sleep(0.02)

if not fired:
    print("No alert fired — needs at least 30 packets. Is the backend running?")
else:
    print("\nDone. Refresh your dashboard now — this new attacker should show up as flagged.")
