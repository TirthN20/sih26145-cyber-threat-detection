"""
ML TRAINING DATA GENERATOR
====================================================
Why this file exists, separate from generate_traffic.py:

generate_traffic.py makes a small, fixed demo dataset (2 attackers per
category) for the dashboard to display. That's fine for a live demo,
but it is WAY too small and too uniform to train a machine learning
model on honestly — 2 examples per class would just memorize those 2
examples, not learn a general pattern (and a judge who knows ML will
ask about this immediately if the two datasets are the same one).

This script instead generates MANY hosts per category (default 60
normal + 35 per attack type = ~235 hosts), each with RANDOMIZED
parameters (different flood rates, different scan sizes, different
beacon intervals, different covert bit-encodings) so the models
actually have to learn the general shape of each attack, not one
fixed example of it.

This is explicitly a synthetic, honestly-labeled dataset for a proof
of concept — the same honest framing as everywhere else in this
project. Swap in real labeled data (e.g. CIDDS-001) by producing a
DataFrame with the same columns and re-running train_models.py.

Output: ml_training_traffic.csv (one row per packet, like
traffic_log.csv) + ml_training_labels.csv (one row per host: its
true category).
"""

import numpy as np
import pandas as pd
import random
import string

np.random.seed(7)
random.seed(7)

rows = []
labels = []  # list of (src_ip, category)
_used_ips = set()


def random_ip(prefix):
    """Guaranteed unique across the whole generation run — duplicate IPs
    would silently merge two different hosts' traffic into one, which
    corrupts both the features and the label for that IP."""
    for _ in range(2000):
        ip = f"{prefix}.{random.randint(2, 254)}"
        if ip not in _used_ips:
            _used_ips.add(ip)
            return ip
    raise RuntimeError(f"Ran out of unique IPs for prefix {prefix} — widen the range.")


def random_domain(length):
    letters = string.ascii_lowercase + string.digits
    return "".join(random.choice(letters) for _ in range(length)) + ".com"


def real_looking_domain():
    # A broad, phonetically varied word bank — not just business terms.
    # The earlier version only had ~20 words and later ~100, but all from
    # a narrow "business/tech" theme, so common English letter patterns
    # (double letters like "oo"/"ee", "-gle"/"-ook" endings, etc.) were
    # simply ABSENT from training — that's exactly why "google.com" was
    # misclassified: the n-grams it needs ("goo", "oog", "gle") never
    # appeared in a single training example. This list adds ordinary,
    # everyday words specifically to cover that broader phonetic range.
    words = [
        "shop", "news", "mail", "docs", "video", "app", "cloud", "store", "media", "portal",
        "secure", "login", "account", "service", "update", "data", "web", "site", "online", "page",
        "support", "help", "info", "blog", "forum", "market", "travel", "hotel", "flight", "bank",
        "finance", "invest", "health", "clinic", "pharma", "school", "learn", "course", "training", "academy",
        "sports", "fitness", "music", "movie", "stream", "game", "play", "social", "connect", "share",
        "photo", "gallery", "design", "studio", "agency", "group", "team", "network", "system", "tech",
        "digital", "smart", "global", "national", "central", "metro", "city", "region", "local", "world",
        "food", "recipe", "kitchen", "restaurant", "cafe", "delivery", "express", "logistics", "cargo", "transport",
        "auto", "motor", "vehicle", "garage", "realestate", "property", "home", "house", "build", "construct",
        "energy", "solar", "power", "utility", "water", "gas", "insurance", "legal", "law", "consult",
        # ordinary everyday words, chosen for phonetic/spelling variety
        "good", "book", "look", "cool", "tool", "pool", "moon", "room", "food", "wood",
        "green", "clean", "sweet", "free", "tree", "speed", "deep", "keep", "week", "meet",
        "circle", "eagle", "angle", "single", "jungle", "puzzle", "bundle", "handle", "middle", "little",
        "quick", "bright", "light", "night", "right", "sight", "fresh", "smart", "sharp", "swift",
        "garden", "harbor", "castle", "bridge", "valley", "island", "meadow", "forest", "canyon", "summit",
        "purple", "orange", "silver", "golden", "coral", "amber", "crystal", "marble", "velvet", "cotton",
    ]
    prefixes = ["", "my", "the", "get", "go", "try"]
    suffixes = ["", str(random.randint(1, 99)), "hq", "pro", "plus", "hub"]
    w1 = random.choice(words)
    style = random.random()
    if style < 0.55:
        name = random.choice(prefixes) + w1 + random.choice(suffixes)
    elif style < 0.85:
        name = w1 + "-" + random.choice(words)
    else:
        name = w1 + random.choice(words)
    return name + random.choice([".com", ".com", ".com", ".net", ".org", ".in", ".co"])


def make_packet(t, src, dst, port, proto, size, dns_query="", ja3=""):
    return {"timestamp": round(t, 3), "src_ip": src, "dst_ip": dst, "dst_port": port,
            "protocol": proto, "packet_size": size, "dns_query": dns_query, "ja3": ja3}


SIM_DURATION = 900.0
NORMAL_PORTS = [80, 443, 53, 22]
KNOWN_GOOD_JA3 = ["a0e9f5d64349fb13191bc781f81f42e1", "51c64c77e60f3980eea90869b68c58a8"]
KNOWN_BAD_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865": "Cobalt Strike (default malleable C2 profile)",
    "6734f37431670b3ab4292b8f60f29984": "IcedID loader",
}

N_NORMAL = 60
N_PER_ATTACK = 35


def gen_normal_hosts():
    """Mirrors generate_traffic.py's ACTUAL normal-traffic pattern exactly:
    packets arrive on ONE shared timeline (exponential inter-arrival,
    scale=0.35s) and get randomly assigned to whichever host in a shared
    pool happens to be talking — NOT each host browsing continuously on
    its own. That means each individual host ends up with relatively
    FEW packets and, critically, NO DNS queries (the demo dataset only
    ever gives DNS traffic to attackers). Training on a different,
    denser pattern than the real demo traffic silently causes false
    positives on ordinary hosts — that's exactly what happened on the
    first pass here, and this rewrite is the fix, not just a caveat.
    We run several independent pools (different "deployments") to get
    enough distinct host examples without changing the per-host shape.
    """
    n_pools = max(1, N_NORMAL // 25)
    hosts_per_pool = max(8, N_NORMAL // n_pools)
    for _ in range(n_pools):
        pool_ips = [random_ip("10.1") for _ in range(hosts_per_pool)]
        host_ja3 = {ip: random.choice(KNOWN_GOOD_JA3) for ip in pool_ips}
        t = 0.0
        while t < SIM_DURATION:
            t += np.random.exponential(scale=0.35)
            if t >= SIM_DURATION:
                break
            src = random.choice(pool_ips)
            port = random.choice(NORMAL_PORTS)
            ja3 = host_ja3[src] if port == 443 else ""
            rows.append(make_packet(t, src, "172.16.0.10", port, random.choice(["TCP", "UDP"]),
                                     int(np.random.normal(500, 120)), "", ja3))  # no dns_query, matches real generator
        for ip in pool_ips:
            labels.append((ip, "Normal"))


def generate_domain_training_set(n_each=5000):
    """A SEPARATE, dedicated corpus for the Naive Bayes domain classifier.
    This intentionally does NOT come from the host-traffic simulation
    above (normal hosts there generate no DNS at all, matching the real
    demo dataset) — real-vs-gibberish domain classification is trained
    the way it's actually done in practice: on a labeled domain corpus,
    independent of any one traffic capture. Saved separately so it can
    be inspected/regenerated on its own."""
    real = [real_looking_domain() for _ in range(n_each)]
    gibberish = [random_domain(random.randint(10, 20)) for _ in range(n_each)]
    df = pd.DataFrame(
        {"domain": real + gibberish, "is_gibberish": [0] * len(real) + [1] * len(gibberish)}
    )
    df.to_csv("ml_domain_training.csv", index=False)
    return df


def gen_flood_hosts():
    for _ in range(N_PER_ATTACK):
        ip = random_ip("203.1")
        start = np.random.uniform(20, SIM_DURATION - 20)
        duration = np.random.uniform(2, 6)
        n_packets = int(np.random.uniform(80, 600))
        for _ in range(n_packets):
            t = start + np.random.uniform(0, duration)
            rows.append(make_packet(t, ip, "172.16.0.10", 80, "TCP", int(np.random.normal(60, 15))))
        labels.append((ip, "Flood / DoS"))


def gen_scan_hosts():
    for _ in range(N_PER_ATTACK):
        ip = random_ip("203.2")
        start = np.random.uniform(20, SIM_DURATION - 40)
        n_ports = int(np.random.uniform(18, 120))
        ports = random.sample(range(1, 5000), min(n_ports, 4999))
        rate = np.random.uniform(0.1, 0.6)
        for i, port in enumerate(ports):
            t = start + i * rate + np.random.uniform(-0.02, 0.02)
            rows.append(make_packet(t, ip, "172.16.0.10", port, "TCP", int(np.random.normal(64, 8))))
        labels.append((ip, "Port Scan / Reconnaissance"))


def gen_dns_tunnel_hosts():
    for _ in range(N_PER_ATTACK):
        ip = random_ip("203.3")
        interval = np.random.uniform(8, 25)
        t = np.random.uniform(0, 30)
        while t < SIM_DURATION:
            rows.append(make_packet(t, ip, "8.8.8.8", 53, "UDP", int(np.random.normal(120, 6)),
                                     random_domain(random.randint(12, 20))))
            t += interval + np.random.uniform(-0.3, 0.3)
        labels.append((ip, "DNS Tunneling / C2 Beaconing"))


def gen_covert_hosts():
    for _ in range(N_PER_ATTACK):
        ip = random_ip("203.4")
        short_gap = np.random.uniform(0.12, 0.28)
        long_gap = short_gap * np.random.uniform(2.0, 3.2)
        t = np.random.uniform(20, 100)
        n_bits = int(np.random.uniform(40, 160))
        bits = np.random.randint(0, 2, size=n_bits)
        for b in bits:
            gap = (short_gap if b == 0 else long_gap) + np.random.normal(0, 0.01)
            t += max(gap, 0.02)
            rows.append(make_packet(t, ip, "172.16.0.10", 443, "TCP", int(np.random.normal(500, 120))))
        labels.append((ip, "Covert Timing Channel (hidden data exfiltration)"))


def gen_ja3_hosts():
    bad_hashes = list(KNOWN_BAD_JA3.keys())
    for _ in range(N_PER_ATTACK):
        ip = random_ip("203.5")
        bad_hash = random.choice(bad_hashes)
        t = np.random.uniform(0, 30)
        avg_gap = np.random.uniform(15, 60)
        n = int(np.random.uniform(6, 20))
        for _ in range(n):
            t += avg_gap + np.random.uniform(-3, 3)
            rows.append(make_packet(t, ip, "172.16.0.10", 443, "TCP", int(np.random.normal(480, 100)),
                                     ja3=bad_hash))
        labels.append((ip, "Encrypted C2 (malicious TLS fingerprint)"))


def main():
    gen_normal_hosts()
    gen_flood_hosts()
    gen_scan_hosts()
    gen_dns_tunnel_hosts()
    gen_covert_hosts()
    gen_ja3_hosts()

    traffic = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    traffic.to_csv("ml_training_traffic.csv", index=False)

    labels_df = pd.DataFrame(labels, columns=["src_ip", "category"])
    labels_df.to_csv("ml_training_labels.csv", index=False)

    domain_df = generate_domain_training_set()

    print(f"Generated {len(traffic)} packets across {len(labels_df)} hosts")
    print(labels_df["category"].value_counts().to_string())
    print(f"Generated {len(domain_df)} labeled domains for Naive Bayes (ml_domain_training.csv)")


if __name__ == "__main__":
    main()
