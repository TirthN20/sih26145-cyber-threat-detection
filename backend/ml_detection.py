"""
ML-DRIVEN DETECTION, ORGANIZED INTO 5 SPEED LAYERS (the AI path)
====================================================
Every decision here still comes entirely from a trained model —
nothing in this file is a hand-written "if count > threshold" rule.
What's new: the 5-layer, 5-speed structure from the original design
is back, because it's a genuinely good story and there's no reason to
give it up just because the DECIDING mechanism changed.

Here's how the two ideas fit together without contradicting each
other: Random Forest can often guess a host's category from just a
handful of packets, but a guess from 3 packets and a guess from 300
packets don't deserve the same trust. So each category has its own
"how much evidence before we act on the AI's answer" gate — Instant
needs almost none (a single malicious TLS fingerprint is conclusive
on its own), Very Slow needs a lot (a covert timing pattern only
becomes real evidence once there's enough of it to rule out random
chance). The AI decides WHAT it's seeing as soon as it's seen enough
to guess; the layer decides WHEN that guess is trustworthy enough to
act on. Both jobs matter, and they're deliberately separate.

Two models do the actual deciding:
  - Random Forest    -> classifies into one of the 5 known categories.
                         This is what raises the 5 category-based layers.
  - Isolation Forest  -> the 6th layer, a safety net trained ONLY on
                         normal traffic. Flags anything Random Forest
                         doesn't confidently recognize — including
                         attack types neither model was ever taught.
"""

import numpy as np
import ml_models as mm

ML_CONFIDENCE_THRESHOLD = 0.40  # Random Forest confidence needed to raise an alert.
# Not a high bar like 0.8 on purpose — with 6 possible classes, even a
# correct top prediction often sits under 50% while evidence is still
# building. Confidence is expected to be a genuinely evolving number,
# not a switch that flips from 0 to 99.

# ---------------------------------------------------------------------
# THE 5 LAYERS — same names, same speed philosophy as the original
# design. "min_evidence" mirrors the thresholds the old rule-based
# system used (FLOOD_THRESHOLD, SCAN_THRESHOLD, MIN_BEACON_EVENTS,
# MIN_COVERT_EVENTS) — not because a rule decides anymore, but because
# those numbers were already a well-reasoned answer to "how much
# evidence does THIS attack type realistically need before you can
# trust a verdict on it," and that reasoning doesn't stop being true
# just because a model is doing the classifying now.
# ---------------------------------------------------------------------
CATEGORY_LAYER_INFO = {
    "Encrypted C2 (malicious TLS fingerprint)": {
        "layer_key": "Layer 0 (instant, JA3 fingerprint)",
        "evidence_feature": "packet_count", "min_evidence": 1,
    },
    "Flood / DoS": {
        "layer_key": "Layer 1 (fast, 5s)",
        "evidence_feature": "packet_count", "min_evidence": 5,
    },
    "Port Scan / Reconnaissance": {
        "layer_key": "Layer 2 (medium, 30s)",
        "evidence_feature": "packet_count", "min_evidence": 15,
    },
    "DNS Tunneling / C2 Beaconing": {
        "layer_key": "Layer 3 (slow, DNS pattern)",
        "evidence_feature": "dns_count", "min_evidence": 5,
    },
    "Covert Timing Channel (hidden data exfiltration)": {
        "layer_key": "Layer 4 (very slow, covert channel)",
        "evidence_feature": "packet_count", "min_evidence": 30,
    },
}

BASELINE_MIN_PACKETS = 3
# The absolute floor before we even ASK the model anything (unless a
# JA3 match already makes the question moot) — see ml_features.py:
# with 1-2 packets, most features are still zero (no session length
# yet, no timing pattern yet), which is a kind of input the model
# never saw in training and can extrapolate badly on. 3 packets is
# enough for the feature vector to at least be non-degenerate; the
# per-category gates above do the real work of pacing each layer.


def _decode_covert_bits(timestamps, max_bits=60):
    """Turns packet-timing gaps back into the 0/1 message they encode —
    pure signal processing, used only to SHOW the evidence behind an
    already-made classification, not to make the classification."""
    times = np.sort(np.asarray(timestamps, dtype=float))
    gaps = np.diff(times)
    if len(gaps) < 4:
        return ""
    rounded = np.round(gaps / 0.05) * 0.05
    values, counts = np.unique(rounded, return_counts=True)
    if len(values) < 2:
        return ""
    order = np.argsort(-counts)
    two_values = sorted(values[order[:2]])
    short_val, long_val = two_values[0], two_values[1]
    mid = (short_val + long_val) / 2
    return "".join("0" if g < mid else "1" for g in gaps[:max_bits])


def _find_ja3_match(host_df, ja3_feed_dict):
    for h in host_df["ja3"].fillna(""):
        if h and h in ja3_feed_dict:
            return h, ja3_feed_dict[h]
    return "", ""


def _model_opinions(pred, verdict_model):
    """One structured entry per trained model's verdict on this host —
    meant to be SHOWN (as chips/badges on an alert card), not just read
    inside a paragraph. This is what actually populates ml_predictions
    now: one row per model, per alert, so 'which of our 6 models caught
    this' is a real, queryable answer, not just a claim in a sentence.
    verdict_model marks which ONE of these is the actual decision-maker
    for this specific alert — the other 4 are corroborating opinions,
    not co-equal votes."""
    rf, iso = pred["random_forest"], pred["isolation_forest"]
    lr, dt, km = pred["logistic_regression"], pred["decision_tree"], pred["kmeans"]
    opinions = [
        {"model": "random_forest", "predicted_label": rf["predicted_label"],
         "confidence": rf["confidence"]},
        {"model": "isolation_forest",
         "predicted_label": "Anomaly" if iso["is_anomaly"] else "Normal",
         "confidence": min(0.99, iso["anomaly_score"] * 4)},
        {"model": "logistic_regression",
         "predicted_label": "Flood" if lr["flood_probability"] >= 0.5 else "Not flood",
         "confidence": lr["flood_probability"]},
        {"model": "decision_tree", "predicted_label": dt["predicted_label"],
         "confidence": None},
        {"model": "kmeans", "predicted_label": f"Cluster {km['cluster']}",
         "confidence": None},
    ]
    for op in opinions:
        op["is_final_verdict"] = (op["model"] == verdict_model)
    return opinions


def detect_via_ml(host_df, src_ip, ja3_feed_dict, now=None):
    """Runs the trained models against this host's traffic so far and
    returns a list of NEW alert dicts (0, 1, or 2 entries), each tagged
    with the layer its category belongs to."""
    if len(host_df) == 0:
        return []

    bad_ja3_hashes = set(ja3_feed_dict.keys())
    has_ja3_evidence = bool(set(host_df["ja3"].fillna("")) & bad_ja3_hashes)

    if not has_ja3_evidence and len(host_df) < BASELINE_MIN_PACKETS:
        return []

    pred = mm.predict_all(host_df, bad_ja3_hashes)
    feats = pred["features_used"]
    ts = now if now is not None else float(host_df["timestamp"].max())
    alerts = []

    rf = pred["random_forest"]
    category = rf["predicted_label"]
    if category != "Normal" and rf["confidence"] >= ML_CONFIDENCE_THRESHOLD:
        layer_info = CATEGORY_LAYER_INFO.get(category)
        if category == "Encrypted C2 (malicious TLS fingerprint)":
            # This category's real evidence IS a JA3 match — not packet
            # count. Without one, a classification here is exactly the
            # same kind of ungrounded guess the evidence gates exist to
            # prevent, so it's a hard requirement, not just an exemption
            # from the count-based gates below.
            evidence_ready = has_ja3_evidence
        else:
            evidence_value = feats.get(layer_info["evidence_feature"], 0) if layer_info else 0
            evidence_ready = bool(layer_info) and evidence_value >= layer_info["min_evidence"]

        if layer_info and evidence_ready:
            # Anchor the alert's timestamp to the EARLIEST moment this
            # category's evidence threshold was actually satisfied, not
            # just "whenever we happened to check." Matters most during
            # bulk seeding, where the whole session is available at
            # once — without this, latency would be measured against
            # the wrong end of the data.
            if layer_info["evidence_feature"] == "dns_count":
                relevant_ts = np.sort(host_df[host_df["dns_query"].fillna("") != ""]["timestamp"].to_numpy())
            else:
                relevant_ts = np.sort(host_df["timestamp"].to_numpy())
            n = layer_info["min_evidence"]
            anchor_ts = float(relevant_ts[n - 1]) if len(relevant_ts) >= n else ts

            decoded_bits, ja3_hash, matched_threat = "", "", ""
            if "Covert" in category:
                decoded_bits = _decode_covert_bits(host_df["timestamp"].to_numpy())
            if "Encrypted C2" in category:
                ja3_hash, matched_threat = _find_ja3_match(host_df, ja3_feed_dict)

            explanation = (
                f"Random Forest classified {src_ip} as \u201c{category}\u201d with "
                f"{rf['confidence']*100:.1f}% confidence, using {int(feats['packet_count'])} "
                f"packets seen so far \u2014 enough evidence for this layer's threshold "
                f"({layer_info['evidence_feature']} \u2265 {layer_info['min_evidence']})."
            )

            alerts.append({
                "model_used": "random_forest",
                "layer": layer_info["layer_key"],
                "category": category,
                "confidence_percent": round(rf["confidence"] * 100, 1),
                "explanation": explanation,
                "timestamp": anchor_ts,
                "decoded_bits": decoded_bits,
                "ja3": ja3_hash,
                "matched_threat": matched_threat,
                "model_opinions": _model_opinions(pred, "random_forest"),
            })

    iso = pred["isolation_forest"]
    rf_missed_it = category == "Normal" or rf["confidence"] < ML_CONFIDENCE_THRESHOLD
    if iso["is_anomaly"] and rf_missed_it:
        confidence = min(99.0, iso["anomaly_score"] * 400)
        alerts.append({
            "model_used": "isolation_forest",
            "layer": "Layer 5 (catch-all, anomaly detector)",
            "category": "Unclassified Anomaly",
            "confidence_percent": round(confidence, 1),
            "explanation": (
                f"Isolation Forest flagged {src_ip} as anomalous (score "
                f"{iso['anomaly_score']:.3f}) even though Random Forest didn't "
                f"confidently match it to a known attack type. Trained ONLY "
                f"on normal traffic, this model can catch a genuinely new "
                f"technique none of the other 5 layers were built to recognize."
            ),
            "timestamp": ts,
            "decoded_bits": "", "ja3": "", "matched_threat": "",
            "model_opinions": _model_opinions(pred, "isolation_forest"),
        })

    return alerts
