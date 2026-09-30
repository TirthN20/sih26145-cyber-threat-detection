"""
FEATURE ENGINEERING
====================================================
Turns one host's raw packets into a fixed-length numeric feature
vector that a machine learning model can actually learn from. This
is the single most important file in the ML pipeline — a model is
only as good as the features it's given, and every feature here is
directly traceable back to the rule-based logic in detection.py, so
the ML layer is learning the SAME signals we already know matter,
just weighing and combining them automatically instead of by hand.

Used identically by train_models.py (on the training dataset) and by
main_mysql.py (on live traffic) — this guarantees training and
inference never quietly drift apart.
"""

import numpy as np
import pandas as pd

FEATURE_NAMES = [
    "packet_count",
    "session_duration",
    "max_rate_5s",
    "max_distinct_ports_30s",
    "dns_count",
    "dns_timing_cv",
    "dns_avg_entropy",
    "gap_top2_share",
    "gap_separation_ratio",
    "avg_packet_size",
    "tcp_ratio",
    "has_bad_ja3",
]


def _shannon_entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * np.log2(p) for p in probs)


def _max_rate_5s(ts):
    if len(ts) == 0:
        return 0
    ts = np.sort(ts)
    j, best = 0, 0
    for i in range(len(ts)):
        while ts[i] - ts[j] > 5.0:
            j += 1
        best = max(best, i - j + 1)
    return best


def _max_distinct_ports_30s(ts, ports):
    if len(ts) == 0:
        return 0
    order = np.argsort(ts)
    ts, ports = ts[order], np.asarray(ports)[order]
    from collections import Counter
    j, best = 0, 0
    counts = Counter()
    for i in range(len(ts)):
        counts[ports[i]] += 1
        while ts[i] - ts[j] > 30.0:
            counts[ports[j]] -= 1
            if counts[ports[j]] == 0:
                del counts[ports[j]]
            j += 1
        best = max(best, len(counts))
    return best


def extract_features(host_df, bad_ja3_hashes=None):
    """host_df: a DataFrame already filtered to one src_ip, with columns
    timestamp, dst_port, protocol, packet_size, dns_query, ja3.
    Returns a dict of FEATURE_NAMES -> float. Never raises on empty/
    partial data — always returns a complete, well-defined vector."""
    bad_ja3_hashes = bad_ja3_hashes or set()
    ts = host_df["timestamp"].to_numpy(dtype=float)
    n = len(ts)

    feats = {name: 0.0 for name in FEATURE_NAMES}
    feats["packet_count"] = float(n)
    if n == 0:
        return feats

    feats["session_duration"] = float(ts.max() - ts.min())
    feats["max_rate_5s"] = float(_max_rate_5s(ts))
    feats["max_distinct_ports_30s"] = float(
        _max_distinct_ports_30s(ts, host_df["dst_port"].fillna(0).to_numpy())
    )
    feats["avg_packet_size"] = float(host_df["packet_size"].fillna(0).mean())
    proto = host_df["protocol"].fillna("")
    feats["tcp_ratio"] = float((proto == "TCP").mean()) if n else 0.0

    dns_df = host_df[host_df["dns_query"].fillna("") != ""]
    feats["dns_count"] = float(len(dns_df))
    if len(dns_df) >= 3:
        dns_ts = np.sort(dns_df["timestamp"].to_numpy(dtype=float))
        gaps = np.diff(dns_ts)
        if gaps.mean() > 0:
            feats["dns_timing_cv"] = float(gaps.std() / gaps.mean())
        feats["dns_avg_entropy"] = float(
            np.mean([_shannon_entropy(q) for q in dns_df["dns_query"]])
        )
    else:
        feats["dns_timing_cv"] = 1.0  # "no beacon pattern" default, not 0 (0 would look robotic)

    if n >= 5:
        gaps = np.diff(np.sort(ts))
        gaps = gaps[gaps > 0]
        if len(gaps) >= 4:
            rounded = np.round(gaps / 0.05) * 0.05
            values, counts = np.unique(rounded, return_counts=True)
            proportions = counts / counts.sum()
            order = np.argsort(-proportions)
            feats["gap_top2_share"] = float(proportions[order[: min(2, len(order))]].sum())
            if len(values) > 1:
                v1, v2 = values[order[0]], values[order[1]]
                feats["gap_separation_ratio"] = float(max(v1, v2) / max(min(v1, v2), 0.001))
            else:
                feats["gap_separation_ratio"] = 1.0

    ja3_vals = set(host_df["ja3"].fillna("")) - {""}
    feats["has_bad_ja3"] = 1.0 if (ja3_vals & bad_ja3_hashes) else 0.0

    return feats


def build_feature_table(traffic_df, hosts, bad_ja3_hashes=None):
    """hosts: iterable of src_ip strings. Returns a DataFrame, one row
    per host, columns = FEATURE_NAMES, indexed by src_ip."""
    rows = {}
    for ip in hosts:
        host_df = traffic_df[traffic_df["src_ip"] == ip]
        rows[ip] = extract_features(host_df, bad_ja3_hashes)
    return pd.DataFrame.from_dict(rows, orient="index", columns=FEATURE_NAMES)
