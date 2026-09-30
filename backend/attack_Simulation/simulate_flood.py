"""
SIMULATE A LIVE ATTACK
====================================================
Sends a burst of packets to your running backend's /api/ingest
endpoint, one at a time, to trigger a REAL alert in real time — this
is what actually proves the live detection works, not just a single
packet (which is too little evidence on its own to trigger anything).

Requires the backend to already be running:
    uvicorn main_mysql:app --reload

Usage:
    python simulate_attack.py
"""

import requests
import time

API = "http://127.0.0.1:8000/api/ingest"
NEW_ATTACKER_IP = "203.0.113.60"    # change this if you re-run more than once
START_TIME = 2000.0                 # any timestamp far from existing data is fine

print(f"Simulating a flood attack from {NEW_ATTACKER_IP} ...")
fired = False
for i in range(60):
    t = START_TIME + (i * 3.0 / 60.0)  # 60 packets spread across 3 seconds = a real flood
    r = requests.post(API, json={
        "timestamp": t, "src_ip": NEW_ATTACKER_IP, "dst_ip": "172.16.0.10",
        "dst_port": 80, "protocol": "TCP", "packet_size": 60,
    })
    result = r.json()
    if result["new_alerts"] and not fired:
        fired = True
        print(f"\nALERT FIRED at packet #{i+1}:")
        for a in result["new_alerts"]:
            print(f"  category: {a['category']}")
            print(f"  confidence: {a['confidence_percent']}%")
            print(f"  explanation: {a['explanation']}")
    time.sleep(0.02)

if not fired:
    print("No alert fired — is the backend running? Check the URL above.")
else:
    print("\nDone. Refresh your dashboard now — this new attacker should show up as flagged.")
