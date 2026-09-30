"""
GENERATE A LIVE-STREAM TEST DATASET
====================================================
Smaller and faster than generate_large_test_dataset.py (150 hosts,
which takes too long to stream packet-by-packet for a live demo) —
this makes a lighter set (about 50 hosts, 3 attackers per category)
specifically meant to be streamed into your ALREADY-RUNNING system
via live_stream_test.py, on top of your existing 3763-packet demo
data, not replacing it.

Uses DIFFERENT IP ranges than traffic_log.csv (10.0.1.x for normal,
203.0.114.x / 198.51.101.x for attackers — one octet higher than the
demo data's 10.0.0.x / 203.0.113.x / 198.51.100.x) so there is ZERO
chance of colliding with your existing 38 demo hosts.

Usage:
    python3 generate_live_stream_dataset.py
"""

import numpy as np
import pandas as pd
import random
import string
import json

np.random.seed(2026)
random.seed(2026)

rows = []
ground_truth = {}
_used_ips = set()

SIM_DURATION = 300.0
N_NORMAL_HOSTS = 24
N_PER_ATTACK_CATEGORY = 3  # 3 x 5 = 15 attackers

with open("ja3_threat_feed.json") as f:
    MALICIOUS_FEED = json.load(f)
MALICIOUS_JA3_LIST = [e["ja3"] for e in MALICIOUS_FEED]

BENIGN_JA3 = [
    "769,47-53-5-10-49161-49162,0-10-11,23-24,0",
    "771,4865-4866-4867,0-23-65281,29-23-24,0",
]
COMMON_PORTS = [80, 443, 53, 22]


def random_ip(prefix):
    for _ in range(2000):
        ip = f"{prefix}.{random.randint(2, 254)}"
        if ip not in _used_ips:
            _used_ips.add(ip)
            return ip
    raise RuntimeError(f"ran out of unique IPs for {prefix}")


def random_domain(length=16):
    letters = string.ascii_lowercase + string.digits
    return "".join(random.choice(letters) for _ in range(length)) + ".com"


def add(t, src, dst, port, proto, size, dns="", ja3=""):
    rows.append({"timestamp": round(t, 3), "src_ip": src, "dst_ip": dst, "dst_port": port,
                 "protocol": proto, "packet_size": size, "dns_query": dns, "ja3": ja3})


# ---------------- NORMAL BACKGROUND TRAFFIC (10.0.1.x — distinct from demo's 10.0.0.x) ----------------
normal_ips = [random_ip("10.0.1") for _ in range(N_NORMAL_HOSTS)]
normal_ja3 = {ip: random.choice(BENIGN_JA3) for ip in normal_ips}
t = 0.0
while t < SIM_DURATION:
    t += np.random.exponential(scale=0.35)
    if t >= SIM_DURATION:
        break
    src = random.choice(normal_ips)
    port = random.choice(COMMON_PORTS)
    ja3 = normal_ja3[src] if port == 443 else ""
    add(t, src, "172.16.0.10", port, random.choice(["TCP", "UDP"]),
        int(np.random.normal(500, 120)), "", ja3)

# ---------------- FLOOD / DoS (203.0.114.x — distinct from demo's 203.0.113.x) ----------------
for _ in range(N_PER_ATTACK_CATEGORY):
    ip = random_ip("203.0.114")
    start = np.random.uniform(10, SIM_DURATION - 10)
    n_packets = int(np.random.uniform(150, 350))
    for _ in range(n_packets):
        add(start + np.random.uniform(0, 3), ip, "172.16.0.10", 80, "TCP", int(np.random.normal(60, 12)))
    ground_truth[ip] = "Flood / DoS"

# ---------------- PORT SCAN (198.51.101.x — distinct from demo's 198.51.100.x) ----------------
for _ in range(N_PER_ATTACK_CATEGORY):
    ip = random_ip("198.51.101")
    start = np.random.uniform(10, SIM_DURATION - 20)
    n_ports = int(np.random.uniform(30, 70))
    for i, port in enumerate(random.sample(range(1, 5000), n_ports)):
        add(start + i * 0.3 + np.random.uniform(0, 0.05), ip, "172.16.0.10", port, "TCP",
            int(np.random.normal(64, 6)))
    ground_truth[ip] = "Port Scan / Reconnaissance"

# ---------------- DNS TUNNELING ----------------
for _ in range(N_PER_ATTACK_CATEGORY):
    ip = random_ip("203.0.114")
    t = np.random.uniform(0, 20)
    interval = np.random.uniform(10, 18)
    while t < SIM_DURATION:
        add(t, ip, "8.8.8.8", 53, "UDP", int(np.random.normal(120, 6)), random_domain())
        t += interval + np.random.uniform(-0.3, 0.3)
    ground_truth[ip] = "DNS Tunneling / C2 Beaconing"

# ---------------- COVERT TIMING CHANNEL ----------------
for _ in range(N_PER_ATTACK_CATEGORY):
    ip = random_ip("198.51.101")
    short_gap = np.random.uniform(0.15, 0.25)
    long_gap = short_gap * np.random.uniform(2.3, 3.0)
    n_bits = int(np.random.uniform(45, 90))
    bits = np.random.randint(0, 2, size=n_bits)
    t = np.random.uniform(10, 40)
    for b in bits:
        t += (short_gap if b == 0 else long_gap) + np.random.normal(0, 0.01)
        add(t, ip, "172.16.0.10", 443, "TCP", int(np.random.normal(500, 120)), "", random.choice(BENIGN_JA3))
    ground_truth[ip] = "Covert Timing Channel (hidden data exfiltration)"

# ---------------- ENCRYPTED C2 (JA3 MATCH) ----------------
for _ in range(N_PER_ATTACK_CATEGORY):
    ip = random_ip("203.0.114")
    bad_hash = random.choice(MALICIOUS_JA3_LIST)
    t = np.random.uniform(0, 20)
    for _ in range(int(np.random.uniform(6, 12))):
        t += np.random.uniform(12, 30)
        if t >= SIM_DURATION:
            break
        add(t, ip, "172.16.0.10", 443, "TCP", int(np.random.normal(480, 100)), "", bad_hash)
    ground_truth[ip] = "Encrypted C2 (malicious TLS fingerprint)"

# ---------------- SAVE (offset all timestamps to start where the demo's 900s session ends) ----------------
df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
df["timestamp"] = df["timestamp"] + 1000.0  # keeps this visually separate on the dashboard's timeline
df.to_csv("live_stream_test.csv", index=False)

with open("live_stream_ground_truth.json", "w") as f:
    json.dump({"attackers": ground_truth, "normal_hosts": normal_ips}, f, indent=2)

print(f"Saved {len(df)} packets across {len(normal_ips) + len(ground_truth)} hosts")
print(f"  {len(normal_ips)} normal hosts, {len(ground_truth)} attackers (3 per category x 5)")
print("Files: live_stream_test.csv, live_stream_ground_truth.json")
print("IP ranges used (10.0.1.x, 203.0.114.x, 198.51.101.x) do not overlap your existing demo data.")
