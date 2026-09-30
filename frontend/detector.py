"""
STEP 2: THE THREAT DETECTOR (the heart of the whole project)
====================================================
Reads traffic_log.csv and runs it through FIVE checks:

    LAYER 0 (instant)              -> Encrypted C2 via known-bad JA3 fingerprint
    LAYER 1 (fast,   ~5 sec)       -> Flood / DoS
    LAYER 2 (medium, ~30 sec)      -> Port scanning
    LAYER 3 (slow, pattern-based)  -> DNS tunneling / beaconing
    LAYER 4 (very slow, whole session) -> Covert timing channels (our unique part)

For every alert we also compute a DETECTION LATENCY: how many seconds
passed between this host's first-ever packet and the moment we caught it.
Faster is better - it's a fair way to compare how "quick" each layer is.

Everything is saved to alerts.csv, ready for the dashboard.
"""

import pandas as pd
import numpy as np
import json

df = pd.read_csv("traffic_log.csv")
df = df.sort_values("timestamp").reset_index(drop=True)
df["dns_query"] = df["dns_query"].fillna("")
df["ja3"] = df["ja3"].fillna("")

# "first seen" time for every host - used to compute detection latency
first_seen = df.groupby("src_ip")["timestamp"].min().to_dict()

alerts = []


def add_alert(layer, category, src_ip, confidence, explanation, timestamp, extra=None):
    latency = max(0.0, timestamp - first_seen.get(src_ip, timestamp))
    row = {
        "timestamp": round(timestamp, 2),
        "layer": layer,
        "category": category,
        "src_ip": src_ip,
        "confidence_percent": round(confidence * 100, 1),
        "explanation": explanation,
        "detection_latency_sec": round(latency, 2),
        "decoded_bits": "",
    }
    if extra:
        row.update(extra)
    alerts.append(row)


# ===================================================================
# LAYER 0 — INSTANT: KNOWN-MALICIOUS JA3 (ENCRYPTED TRAFFIC) FINGERPRINT
# ===================================================================
# TLS-encrypted traffic still exposes one thing before encryption kicks
# in: the "ClientHello" handshake message, which has a fingerprint (JA3)
# based on how the connection is being set up. This is visible even
# though (a) we can't see inside the encrypted data and (b) we only see
# one direction. We compare every JA3 we see against a feed of known
# malicious tool fingerprints.

with open("ja3_threat_feed.json") as f:
    MALICIOUS_FEED = {entry["ja3"]: entry["threat"] for entry in json.load(f)}

tls_rows = df[df["ja3"] != ""]
ja3_matches = tls_rows[tls_rows["ja3"].isin(MALICIOUS_FEED.keys())]

for (src_ip, ja3), group in ja3_matches.groupby(["src_ip", "ja3"]):
    threat_name = MALICIOUS_FEED[ja3]
    first_time = group["timestamp"].min()
    count = len(group)
    add_alert(
        layer="Layer 0 (instant, JA3 fingerprint)",
        category="Encrypted C2 (malicious TLS fingerprint)",
        src_ip=src_ip,
        confidence=0.97,
        explanation=(
            f"{src_ip} made {count} HTTPS connections whose TLS handshake "
            f"fingerprint (JA3 {ja3[:12]}...) exactly matches a known-malicious "
            f"signature in our threat feed: \u201c{threat_name}\u201d. Nothing else "
            f"about this traffic looks unusual - it was caught purely from how "
            f"the encrypted connection was set up, not what's inside it."
        ),
        timestamp=first_time,
        extra={"ja3": ja3, "matched_threat": threat_name},
    )


# ===================================================================
# LAYER 1 — FAST (5 second windows): FLOOD / DoS
# ===================================================================
WINDOW_L1, FLOOD_THRESHOLD = 5.0, 50
max_time = df["timestamp"].max()
window_start, flagged_l1 = 0.0, set()

while window_start < max_time:
    chunk = df[(df["timestamp"] >= window_start) & (df["timestamp"] < window_start + WINDOW_L1)]
    for src_ip, count in chunk["src_ip"].value_counts().items():
        if count > FLOOD_THRESHOLD and src_ip not in flagged_l1:
            flagged_l1.add(src_ip)
            confidence = min(0.99, count / (FLOOD_THRESHOLD * 4))
            add_alert("Layer 1 (fast, 5s)", "Flood / DoS", src_ip, confidence,
                       f"{src_ip} sent {count} packets in a single 5-second window "
                       f"(normal sources send well under {FLOOD_THRESHOLD}).",
                       window_start)
    window_start += WINDOW_L1


# ===================================================================
# LAYER 2 — MEDIUM (30 second windows): PORT SCAN
# ===================================================================
WINDOW_L2, PORT_THRESHOLD = 30.0, 15
window_start, flagged_l2 = 0.0, set()

while window_start < max_time:
    chunk = df[(df["timestamp"] >= window_start) & (df["timestamp"] < window_start + WINDOW_L2)]
    for src_ip, distinct_ports in chunk.groupby("src_ip")["dst_port"].nunique().items():
        if distinct_ports > PORT_THRESHOLD and src_ip not in flagged_l2:
            flagged_l2.add(src_ip)
            confidence = min(0.99, distinct_ports / (PORT_THRESHOLD * 3))
            add_alert("Layer 2 (medium, 30s)", "Port Scan / Reconnaissance", src_ip, confidence,
                       f"{src_ip} probed {distinct_ports} different destination ports "
                       f"within 30 seconds (normal traffic touches only a few).",
                       window_start)
    window_start += WINDOW_L2


# ===================================================================
# LAYER 3 — SLOW: DNS TUNNELING / C2 BEACONING
# ===================================================================
BEACON_CV_THRESHOLD, MIN_EVENTS = 0.15, 5

def shannon_entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * np.log2(p) for p in probs)

dns_rows = df[df["dns_query"] != ""]
for src_ip, group in dns_rows.groupby("src_ip"):
    times = group["timestamp"].sort_values().values
    if len(times) < MIN_EVENTS:
        continue
    gaps = np.diff(times)
    cv = gaps.std() / gaps.mean() if gaps.mean() > 0 else 999
    avg_entropy = group["dns_query"].apply(shannon_entropy).mean()
    if cv < BEACON_CV_THRESHOLD and avg_entropy > 3.5:
        confidence = min(0.99, (1 - cv) * (avg_entropy / 4))
        detect_time = times[MIN_EVENTS - 1]  # the moment we had enough evidence to decide
        add_alert("Layer 3 (slow, DNS pattern)", "DNS Tunneling / C2 Beaconing", src_ip, confidence,
                   f"{src_ip} made {len(times)} DNS lookups with highly regular "
                   f"timing (variation score={cv:.3f}, lower=more robotic) using "
                   f"gibberish-looking domain names (randomness score={avg_entropy:.2f}/4).",
                   detect_time)


# ===================================================================
# LAYER 4 — VERY SLOW: COVERT TIMING CHANNEL (our unique differentiator)
# ===================================================================
MIN_EVENTS_COVERT = 30

for src_ip, group in df.groupby("src_ip"):
    times = group["timestamp"].sort_values().values
    if len(times) < MIN_EVENTS_COVERT:
        continue
    gaps = np.diff(times)
    if gaps.mean() <= 0:
        continue

    rounded = np.round(gaps / 0.05) * 0.05
    values, counts = np.unique(rounded, return_counts=True)
    proportions = counts / counts.sum()
    order = np.argsort(-proportions)
    top1_share = proportions[order[0]]
    top2_share = proportions[order[:2]].sum()

    # how far apart are the two dominant gap-lengths? A real covert channel
    # uses two CLEARLY DIFFERENT gap lengths to encode 0 and 1 (e.g. 0.2s
    # vs 0.55s - nearly 3x apart). Ordinary jitter rounds into two ADJACENT
    # buckets that are barely different (e.g. 0.30s vs 0.35s - close together).
    # This ratio is what actually separates "deliberate encoding" from
    # "natural noise that happened to round into two buckets."
    if len(values) > 1:
        v1, v2 = values[order[0]], values[order[1]]
        separation_ratio = max(v1, v2) / max(min(v1, v2), 0.001)
    else:
        separation_ratio = 1.0

    is_covert = (top2_share > 0.75) and (top1_share < 0.85) and (separation_ratio >= 1.8)
    if is_covert:
        # decode the actual bits: short gap = 0, long gap = 1, using the
        # two dominant bucket values we just found
        two_values = sorted(values[order[:2]])
        short_val, long_val = two_values[0], two_values[1]
        mid = (short_val + long_val) / 2
        decoded = "".join("0" if g < mid else "1" for g in gaps[:60])

        confidence = min(0.99, top2_share * min(separation_ratio / 3, 1.0))
        detect_time = times[MIN_EVENTS_COVERT - 1]  # moment enough evidence accumulated
        add_alert("Layer 4 (very slow, covert channel)",
                   "Covert Timing Channel (hidden data exfiltration)", src_ip, confidence,
                   f"{src_ip}'s packet timing clusters into just 2 dominant gap "
                   f"lengths ({short_val:.2f}s and {long_val:.2f}s) covering "
                   f"{top2_share*100:.0f}% of all packets, {separation_ratio:.1f}x apart "
                   f"from each other. Natural network jitter rounds into adjacent, "
                   f"similar gap lengths - this pattern matches deliberate bit-encoding "
                   f"(short gap = 0, long gap = 1) instead.",
                   detect_time, extra={"decoded_bits": decoded})


# ===================================================================
# SAVE + PRINT
# ===================================================================
alerts_df = pd.DataFrame(alerts).sort_values("timestamp").reset_index(drop=True)
alerts_df.to_csv("alerts.csv", index=False)

print("=" * 70)
print(f"DETECTION COMPLETE — {len(alerts_df)} alerts across {alerts_df['category'].nunique()} categories")
print(f"Average detection latency: {alerts_df['detection_latency_sec'].mean():.2f}s")
print("=" * 70)
for _, row in alerts_df.iterrows():
    print(f"\n[{row['layer']}] {row['category']}  (latency: {row['detection_latency_sec']}s)")
    print(f"   Source: {row['src_ip']}  |  Confidence: {row['confidence_percent']}%")
    print(f"   Why: {row['explanation']}")
print("\nSaved to alerts.csv")
