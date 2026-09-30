"""
SIMULATE DNS TUNNELING / C2 BEACONING
====================================================
Sends DNS lookups at suspiciously REGULAR intervals, using random
gibberish domain names — the two signals this layer looks for: a
robotic check-in rhythm, and high-entropy (non-real-looking) domains.
Needs at least 5 check-ins before the layer has enough evidence to
decide the timing is "too regular" to be human.

Requires the backend to already be running:
    uvicorn main_mysql:app --reload

Usage:
    python simulate_dns_tunnel.py
"""

import random
import string
import requests
import time

API = "http://127.0.0.1:8000/api/ingest"
NEW_ATTACKER_IP = "203.0.113.62"    # change this if you re-run more than once
START_TIME = 4000.0
INTERVAL = 12.0                       # seconds between beacons — very regular on purpose


def gibberish_domain(length=16):
    letters = string.ascii_lowercase + string.digits
    return "".join(random.choice(letters) for _ in range(length)) + ".com"


print(f"Simulating DNS tunneling from {NEW_ATTACKER_IP} ...")
fired = False
t = START_TIME
for i in range(8):
    t += INTERVAL + random.uniform(-0.2, 0.2)  # tiny jitter, still robotic-regular
    r = requests.post(API, json={
        "timestamp": t, "src_ip": NEW_ATTACKER_IP, "dst_ip": "8.8.8.8",
        "dst_port": 53, "protocol": "UDP", "packet_size": 120,
        "dns_query": gibberish_domain(),
    })
    result = r.json()
    if result["new_alerts"] and not fired:
        fired = True
        print(f"\nALERT FIRED at check-in #{i+1}:")
        for a in result["new_alerts"]:
            print(f"  category: {a['category']}")
            print(f"  confidence: {a['confidence_percent']}%")
            print(f"  explanation: {a['explanation']}")
    time.sleep(0.05)

if not fired:
    print("No alert fired — needs at least 5 check-ins. Is the backend running?")
else:
    print("\nDone. Refresh your dashboard now — this new attacker should show up as flagged.")
