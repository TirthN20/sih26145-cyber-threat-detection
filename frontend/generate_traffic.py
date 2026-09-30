"""
STEP 1: GENERATE FAKE (SYNTHETIC) NETWORK TRAFFIC
====================================================
Creates a pretend one-way traffic log to test our detector on, since real
network captures are hard to get (private/sensitive).

Each row = one packet seen going in ONE DIRECTION ONLY:
    timestamp, src_ip, dst_ip, dst_port, protocol, packet_size,
    dns_query   -> filled only for DNS lookups
    ja3         -> filled only for HTTPS (TCP port 443) packets. This is a
                   fingerprint of *how* a TLS connection is being started
                   (which is visible even though the actual traffic is
                   encrypted and even though we only see one direction -
                   it's part of the very first message a client sends).

We generate normal background traffic plus TWO attackers for each of five
threat categories (10 attackers total), so the alert feed looks like a
real, busy monitoring session instead of one example per category.
"""

import numpy as np
import pandas as pd
import random
import string
import json

np.random.seed(42)
random.seed(42)

rows = []


def random_ip(prefix="10.0.0"):
    return f"{prefix}.{random.randint(2, 254)}"


def random_domain(length=10):
    letters = string.ascii_lowercase + string.digits
    return "".join(random.choice(letters) for _ in range(length)) + ".com"


# ---------------------------------------------------------------
# JA3 FINGERPRINTS: a few "benign" ones (normal browsers/apps) and the
# known-malicious ones loaded from our shared threat feed file.
# ---------------------------------------------------------------
BENIGN_JA3 = [
    "769,47-53-5-10-49161-49162,0-10-11,23-24,0",   # looks like a normal browser
    "771,4865-4866-4867,0-23-65281,29-23-24,0",
    "770,49171-49172,0-5-10-11-13,23-24-25,0",
]
with open("ja3_threat_feed.json") as f:
    MALICIOUS_FEED = json.load(f)
MALICIOUS_JA3_LIST = [entry["ja3"] for entry in MALICIOUS_FEED]

NORMAL_SOURCE_IPS = [random_ip() for _ in range(30)]
NORMAL_JA3_MAP = {ip: random.choice(BENIGN_JA3) for ip in NORMAL_SOURCE_IPS}
COMMON_PORTS = [80, 443, 53, 22]
SIM_DURATION_SECONDS = 900

attacker_log = []  # keep track of every attacker we create, for the printout


def log_attacker(ip, category, note=""):
    attacker_log.append((ip, category, note))


# ---------------------------------------------------------------
# PART A: NORMAL BACKGROUND TRAFFIC
# ---------------------------------------------------------------
t = 0.0
while t < SIM_DURATION_SECONDS:
    t += np.random.exponential(scale=0.35)
    if t >= SIM_DURATION_SECONDS:
        break
    src = random.choice(NORMAL_SOURCE_IPS)
    port = random.choice(COMMON_PORTS)
    rows.append({
        "timestamp": round(t, 3), "src_ip": src, "dst_ip": "172.16.0.10",
        "dst_port": port, "protocol": random.choice(["TCP", "UDP"]),
        "packet_size": int(np.random.normal(500, 120)), "dns_query": "",
        "ja3": NORMAL_JA3_MAP[src] if port == 443 else "",
    })
print(f"Generated {len(rows)} normal background packets")


# ---------------------------------------------------------------
# PART B: FLOOD / DoS  (2 attackers - Layer 1 should catch both)
# ---------------------------------------------------------------
def inject_flood(start_time, n_packets, ip):
    for i in range(n_packets):
        rows.append({
            "timestamp": round(start_time + np.random.uniform(0, 3), 3),
            "src_ip": ip, "dst_ip": "172.16.0.10", "dst_port": 80, "protocol": "TCP",
            "packet_size": int(np.random.normal(60, 10)), "dns_query": "", "ja3": "",
        })
    log_attacker(ip, "Flood / DoS", f"{n_packets} packets in ~3s starting at t={start_time}s")

ip1 = random_ip("203.0.113"); inject_flood(120.0, 400, ip1)
ip2 = random_ip("198.51.100"); inject_flood(560.0, 250, ip2)


# ---------------------------------------------------------------
# PART C: PORT SCAN  (2 attackers - Layer 2)
# ---------------------------------------------------------------
def inject_scan(start_time, n_ports, ip, gap=0.3):
    ports = random.sample(range(1, 4000), n_ports)
    for i, port in enumerate(ports):
        rows.append({
            "timestamp": round(start_time + i * gap + np.random.uniform(0, 0.05), 3),
            "src_ip": ip, "dst_ip": "172.16.0.10", "dst_port": port, "protocol": "TCP",
            "packet_size": int(np.random.normal(64, 5)), "dns_query": "", "ja3": "",
        })
    log_attacker(ip, "Port Scan / Reconnaissance", f"probed {n_ports} ports from t={start_time}s")

ip3 = random_ip("203.0.113"); inject_scan(250.0, 60, ip3)
ip4 = random_ip("198.51.100"); inject_scan(700.0, 45, ip4, gap=0.4)


# ---------------------------------------------------------------
# PART D: DNS TUNNELING / BEACONING (2 attackers - Layer 3)
# ---------------------------------------------------------------
def inject_beacon(start_time, interval, ip):
    t = start_time
    while t < SIM_DURATION_SECONDS:
        rows.append({
            "timestamp": round(t, 3), "src_ip": ip, "dst_ip": "8.8.8.8", "dst_port": 53,
            "protocol": "UDP", "packet_size": int(np.random.normal(120, 5)),
            "dns_query": random_domain(16), "ja3": "",
        })
        t += interval + np.random.uniform(-0.2, 0.2)
    log_attacker(ip, "DNS Tunneling / C2 Beaconing", f"beacon every ~{interval}s from t={start_time}s")

ip5 = random_ip("203.0.113"); inject_beacon(60.0, 15, ip5)
ip6 = random_ip("198.51.100"); inject_beacon(300.0, 22, ip6)


# ---------------------------------------------------------------
# PART E: COVERT TIMING CHANNEL (2 attackers - Layer 4, our differentiator)
# ---------------------------------------------------------------
def inject_covert(start_time, ip, short_gap, long_gap, n_bits=150):
    t = start_time
    bits = np.random.randint(0, 2, size=n_bits)
    bitstring = "".join(str(b) for b in bits)
    for bit in bits:
        gap = (short_gap if bit == 0 else long_gap) + np.random.normal(0, 0.01)
        t += gap
        rows.append({
            "timestamp": round(t, 3), "src_ip": ip, "dst_ip": "172.16.0.10", "dst_port": 443,
            "protocol": "TCP", "packet_size": int(np.random.normal(500, 120)),
            "dns_query": "", "ja3": random.choice(BENIGN_JA3),  # looks like normal HTTPS!
        })
    log_attacker(ip, "Covert Timing Channel", f"{n_bits}-bit hidden message, gaps {short_gap}/{long_gap}s")
    return bitstring

ip7 = random_ip("203.0.113"); bits7 = inject_covert(400.0, ip7, 0.20, 0.55)
ip8 = random_ip("198.51.100"); bits8 = inject_covert(750.0, ip8, 0.15, 0.42)


# ---------------------------------------------------------------
# PART F: ENCRYPTED C2 / MALICIOUS TLS FINGERPRINT (2 attackers - new layer)
# ---------------------------------------------------------------
# These attackers don't flood, scan, or beacon obviously - their traffic
# LOOKS like normal, occasional HTTPS check-ins. The only thing wrong with
# them is which JA3 fingerprint their TLS handshake uses, which matches a
# known malicious tool in our threat feed. Nothing else about them is
# suspicious - this tests whether the system can catch threats hiding
# entirely inside "normal-looking" encrypted traffic.
def inject_malicious_tls(start_time, ip, bad_ja3, n_connections):
    t = start_time
    for _ in range(n_connections):
        t += np.random.uniform(20, 45)  # irregular, not obviously robotic
        if t >= SIM_DURATION_SECONDS:
            break
        rows.append({
            "timestamp": round(t, 3), "src_ip": ip, "dst_ip": "172.16.0.10", "dst_port": 443,
            "protocol": "TCP", "packet_size": int(np.random.normal(480, 100)),
            "dns_query": "", "ja3": bad_ja3,
        })
    log_attacker(ip, "Encrypted C2 (malicious TLS fingerprint)",
                 f"JA3 matches known-bad feed entry from t={start_time}s")

ip9 = random_ip("203.0.113"); inject_malicious_tls(80.0, ip9, MALICIOUS_JA3_LIST[0], 14)
ip10 = random_ip("198.51.100"); inject_malicious_tls(500.0, ip10, MALICIOUS_JA3_LIST[2], 10)


# ---------------------------------------------------------------
# SAVE
# ---------------------------------------------------------------
df = pd.DataFrame(rows)
df["ja3"] = df["ja3"].fillna("")
df = df.sort_values("timestamp").reset_index(drop=True)
df.to_csv("traffic_log.csv", index=False)

# save the true covert-channel bit messages separately, purely so the
# dashboard can show "decoded" bits that are honestly derived from the data
with open("covert_ground_truth.json", "w") as f:
    json.dump({ip7: bits7, ip8: bits8}, f)

print(f"\nDONE. Saved {len(df)} total packets to traffic_log.csv\n")
print("Attackers injected this run:")
for ip, cat, note in attacker_log:
    print(f"  [{cat}] {ip}  -  {note}")
