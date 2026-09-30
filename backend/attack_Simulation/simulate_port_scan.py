"""
SIMULATE A PORT SCAN
====================================================
Sends probes to 30 different ports on your fake server, one packet
at a time, through /api/ingest — enough to cross the port-scan
threshold (>15 distinct ports within 30 seconds) and trigger a real,
live alert.

Requires the backend to already be running:
    uvicorn main_mysql:app --reload

Usage:
    python simulate_port_scan.py
"""

import random
import requests
import time

API = "http://127.0.0.1:8000/api/ingest"
NEW_ATTACKER_IP = "203.0.113.61"    # change this if you re-run more than once
START_TIME = 3000.0

random.seed()
ports = random.sample(range(1, 5000), 30)

print(f"Simulating a port scan from {NEW_ATTACKER_IP} ...")
fired = False
for i, port in enumerate(ports):
    t = START_TIME + i * 0.4  # 30 ports over ~12 seconds — well inside the 30s scan window
    r = requests.post(API, json={
        "timestamp": t, "src_ip": NEW_ATTACKER_IP, "dst_ip": "172.16.0.10",
        "dst_port": port, "protocol": "TCP", "packet_size": 64,
    })
    result = r.json()
    if result["new_alerts"] and not fired:
        fired = True
        print(f"\nALERT FIRED at port probe #{i+1} (port {port}):")
        for a in result["new_alerts"]:
            print(f"  category: {a['category']}")
            print(f"  confidence: {a['confidence_percent']}%")
            print(f"  explanation: {a['explanation']}")
    time.sleep(0.02)

if not fired:
    print("No alert fired — is the backend running? Check the URL above.")
else:
    print("\nDone. Refresh your dashboard now — this new attacker should show up as flagged.")
