"""
DETECTION LOGIC (shared by seeding and live ingestion)
====================================================
Same 5 checks as the standalone detector.py, refactored to work on
just ONE HOST's packets at a time, using a genuine SLIDING window
(not fixed/tumbling) — this is actually an improvement over the
tumbling-window approach: a tumbling window can miss a burst that
happens to fall across the boundary between two windows; a sliding
window can't.

This module has no database code and no web code in it on purpose —
it's pure logic, so it's easy to test on its own and easy to reuse
from both seed.py (bulk, historical data) and main.py (one new
packet at a time, in real time).
"""

import numpy as np

FLOOD_WINDOW, FLOOD_THRESHOLD = 5.0, 50
SCAN_WINDOW, SCAN_THRESHOLD = 30.0, 15
BEACON_CV_THRESHOLD, MIN_BEACON_EVENTS = 0.15, 5
MIN_COVERT_EVENTS = 30


def shannon_entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * np.log2(p) for p in probs)


def _max_count_in_sliding_window(timestamps, window):
    """For sorted timestamps, the largest number of points found inside
    any `window`-second span. Classic two-pointer sliding window, O(n)."""
    ts = np.sort(np.asarray(timestamps, dtype=float))
    j, best = 0, 0
    for i in range(len(ts)):
        while ts[i] - ts[j] > window:
            j += 1
        best = max(best, i - j + 1)
    return best


def _max_distinct_in_sliding_window(rows, window):
    """rows: list of (timestamp, value) sorted by timestamp. Returns the
    largest number of DISTINCT values found inside any `window`-second
    span — used for 'how many different ports in any 30s stretch'."""
    rows = sorted(rows, key=lambda r: r[0])
    j, best = 0, 0
    from collections import Counter
    counts = Counter()
    for i in range(len(rows)):
        counts[rows[i][1]] += 1
        while rows[i][0] - rows[j][0] > window:
            counts[rows[j][1]] -= 1
            if counts[rows[j][1]] == 0:
                del counts[rows[j][1]]
            j += 1
        best = max(best, len(counts))
    return best


def detect_flood(timestamps, src_ip, now=None):
    if len(timestamps) == 0:
        return None
    count = _max_count_in_sliding_window(timestamps, FLOOD_WINDOW)
    if count > FLOOD_THRESHOLD:
        confidence = min(0.99, count / (FLOOD_THRESHOLD * 4))
        ts = now if now is not None else max(timestamps)
        return {
            "layer": "Layer 1 (fast, 5s)", "category": "Flood / DoS", "src_ip": src_ip,
            "confidence_percent": round(confidence * 100, 1),
            "explanation": (
                f"{src_ip} sent {count} packets within a single {FLOOD_WINDOW:.0f}-second "
                f"span (normal sources send well under {FLOOD_THRESHOLD})."
            ),
            "timestamp": ts,
        }
    return None


def detect_scan(rows, src_ip, now=None):
    """rows: list of (timestamp, dst_port) for this host."""
    if not rows:
        return None
    distinct = _max_distinct_in_sliding_window(rows, SCAN_WINDOW)
    if distinct > SCAN_THRESHOLD:
        confidence = min(0.99, distinct / (SCAN_THRESHOLD * 3))
        ts = now if now is not None else max(r[0] for r in rows)
        return {
            "layer": "Layer 2 (medium, 30s)", "category": "Port Scan / Reconnaissance", "src_ip": src_ip,
            "confidence_percent": round(confidence * 100, 1),
            "explanation": (
                f"{src_ip} probed {distinct} different destination ports within "
                f"{SCAN_WINDOW:.0f} seconds (normal traffic touches only a few)."
            ),
            "timestamp": ts,
        }
    return None


def detect_dns_tunnel(dns_timestamps, dns_queries, src_ip):
    if len(dns_timestamps) < MIN_BEACON_EVENTS:
        return None
    times = np.sort(np.asarray(dns_timestamps, dtype=float))
    gaps = np.diff(times)
    if gaps.mean() <= 0:
        return None
    cv = gaps.std() / gaps.mean()
    avg_entropy = np.mean([shannon_entropy(q) for q in dns_queries])
    if cv < BEACON_CV_THRESHOLD and avg_entropy > 3.5:
        confidence = min(0.99, (1 - cv) * (avg_entropy / 4))
        return {
            "layer": "Layer 3 (slow, DNS pattern)", "category": "DNS Tunneling / C2 Beaconing", "src_ip": src_ip,
            "confidence_percent": round(confidence * 100, 1),
            "explanation": (
                f"{src_ip} made {len(times)} DNS lookups with highly regular timing "
                f"(variation score={cv:.3f}, lower=more robotic) using gibberish-looking "
                f"domain names (randomness score={avg_entropy:.2f}/4)."
            ),
            "timestamp": float(times[MIN_BEACON_EVENTS - 1]),
        }
    return None


def detect_covert_channel(timestamps, src_ip):
    if len(timestamps) < MIN_COVERT_EVENTS:
        return None
    times = np.sort(np.asarray(timestamps, dtype=float))
    gaps = np.diff(times)
    if gaps.mean() <= 0:
        return None
    rounded = np.round(gaps / 0.05) * 0.05
    values, counts = np.unique(rounded, return_counts=True)
    proportions = counts / counts.sum()
    order = np.argsort(-proportions)
    top1_share = proportions[order[0]]
    top2_share = proportions[order[:2]].sum()
    if len(values) > 1:
        v1, v2 = values[order[0]], values[order[1]]
        separation_ratio = max(v1, v2) / max(min(v1, v2), 0.001)
    else:
        separation_ratio = 1.0
    is_covert = (top2_share > 0.75) and (top1_share < 0.85) and (separation_ratio >= 1.8)
    if not is_covert:
        return None
    two_values = sorted(values[order[:2]])
    short_val, long_val = two_values[0], two_values[1]
    mid = (short_val + long_val) / 2
    decoded = "".join("0" if g < mid else "1" for g in gaps[:60])
    confidence = min(0.99, top2_share * min(separation_ratio / 3, 1.0))
    return {
        "layer": "Layer 4 (very slow, covert channel)",
        "category": "Covert Timing Channel (hidden data exfiltration)", "src_ip": src_ip,
        "confidence_percent": round(confidence * 100, 1),
        "explanation": (
            f"{src_ip}'s packet timing clusters into just 2 dominant gap lengths "
            f"({short_val:.2f}s and {long_val:.2f}s) covering {top2_share*100:.0f}% of all "
            f"packets, {separation_ratio:.1f}x apart from each other. Natural network jitter "
            f"rounds into adjacent, similar gap lengths - this pattern matches deliberate "
            f"bit-encoding (short gap = 0, long gap = 1) instead."
        ),
        "timestamp": float(times[MIN_COVERT_EVENTS - 1]),
        "decoded_bits": decoded,
    }


def detect_ja3_match(ja3_rows, src_ip, ja3_feed):
    """ja3_rows: list of (timestamp, ja3_hash). ja3_feed: dict hash -> threat name."""
    matches = [(t, h) for t, h in ja3_rows if h in ja3_feed]
    if not matches:
        return None
    first_time, matched_hash = min(matches, key=lambda x: x[0])
    threat_name = ja3_feed[matched_hash]
    return {
        "layer": "Layer 0 (instant, JA3 fingerprint)",
        "category": "Encrypted C2 (malicious TLS fingerprint)", "src_ip": src_ip,
        "confidence_percent": 97.0,
        "explanation": (
            f"{src_ip} made {len(matches)} HTTPS connections whose TLS handshake fingerprint "
            f"(JA3 {matched_hash[:12]}...) exactly matches a known-malicious signature in our "
            f"threat feed: \u201c{threat_name}\u201d. Nothing else about this traffic looks "
            f"unusual - it was caught purely from how the encrypted connection was set up."
        ),
        "timestamp": float(first_time),
        "ja3": matched_hash, "matched_threat": threat_name,
    }


def run_all_checks(host_df, src_ip, ja3_feed, now=None):
    """Runs all 5 checks against one host's packets (a pandas DataFrame
    already filtered to src_ip). Returns a list of alert dicts (0 to 5)."""
    alerts = []
    ts_all = host_df["timestamp"].values

    a = detect_flood(ts_all, src_ip, now)
    if a:
        alerts.append(a)

    scan_rows = list(zip(host_df["timestamp"], host_df["dst_port"]))
    a = detect_scan(scan_rows, src_ip, now)
    if a:
        alerts.append(a)

    dns_df = host_df[host_df["dns_query"] != ""]
    a = detect_dns_tunnel(dns_df["timestamp"].values, dns_df["dns_query"].tolist(), src_ip)
    if a:
        alerts.append(a)

    a = detect_covert_channel(ts_all, src_ip)
    if a:
        alerts.append(a)

    ja3_rows = list(zip(host_df["timestamp"], host_df["ja3"].fillna("")))
    ja3_rows = [(t, h) for t, h in ja3_rows if h]
    a = detect_ja3_match(ja3_rows, src_ip, ja3_feed)
    if a:
        alerts.append(a)

    return alerts
