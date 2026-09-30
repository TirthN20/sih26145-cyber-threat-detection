"""
BACKEND API SERVER — MySQL + ML edition
====================================================
This is the production-grade version of the backend: a real MySQL
database instead of SQLite, plus the 6 trained ML models running
alongside the rule-based detection layers (not replacing them —
both run, both are shown, so you can compare a transparent rule
("400 packets in 5 seconds") against a learned model's opinion on
the exact same host).

Setup (see README.md "MySQL backend" section for full detail):
    1. Have MySQL/MariaDB running with the sih26145 database created
    2. cd backend
    3. python3 ml_training_data.py      (once)
    4. python3 train_models.py          (once, trains + saves 6 models)
    5. python3 seed_mysql.py            (loads traffic_log.csv into MySQL)
    6. uvicorn main_mysql:app --reload
    7. open http://127.0.0.1:8000/docs
"""

import asyncio
import time
from typing import Optional

import pandas as pd
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import database_mysql as db
import detection as det  # kept only for reference/comparison; no longer used for alerting
import ml_detection as mld
import ml_models as mm
import geo as geo_module

app = FastAPI(
    title="PS 26145 — Unidirectional Threat Detector API (MySQL + ML)",
    description=(
        "Production backend: MySQL storage, 5 rule-based detection layers, and 6 "
        "explainable ML models (Logistic Regression, Decision Tree, Random Forest, "
        "Naive Bayes, Isolation Forest, K-Means) running alongside them, not "
        "replacing them — every ML prediction is shown next to the transparent "
        "rule that would normally catch the same thing."
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

db.init_db()


def get_ja3_feed_dict():
    conn = db.get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT ja3, threat FROM ja3_feed")
            rows = cur.fetchall()
        return {r["ja3"]: r["threat"] for r in rows}
    finally:
        conn.close()


def fetch_all(query, params=()):
    conn = db.get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall()
    finally:
        conn.close()


def fetch_one(query, params=()):
    rows = fetch_all(query, params)
    return rows[0] if rows else None


# =====================================================================
# SCHEMAS
# =====================================================================
class PacketIn(BaseModel):
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"
    packet_size: int = 0
    dns_query: str = ""
    ja3: str = ""


class DomainIn(BaseModel):
    domain: str


# =====================================================================
# META
# =====================================================================
@app.get("/", tags=["meta"])
def root():
    return {
        "project": "PS 26145 — Unidirectional Threat Detector (MySQL + ML)",
        "docs": "/docs",
        "endpoints": [
            "GET /api/health", "GET /api/stats", "GET /api/alerts",
            "GET /api/traffic", "GET /api/traffic/timeline", "GET /api/hosts/top",
            "GET /api/ports/top", "GET /api/pipeline", "GET /api/ja3-feed",
            "GET /api/geo/{ip}", "POST /api/ingest", "DELETE /api/reset", "WS /ws/live",
            "GET /api/ml/models", "GET /api/ml/predict/{ip}", "POST /api/ml/predict-domain",
        ],
    }


@app.get("/api/health", tags=["meta"])
def health():
    row = fetch_one("SELECT COUNT(*) c FROM traffic")
    return {"status": "ok", "time": time.time(), "packets_in_db": row["c"]}


# =====================================================================
# STATS
# =====================================================================
@app.get("/api/stats", tags=["stats"])
def get_stats():
    packet_count = fetch_one("SELECT COUNT(*) c FROM traffic")["c"]
    active_hosts = fetch_one("SELECT COUNT(DISTINCT src_ip) c FROM traffic")["c"]
    session_length = fetch_one("SELECT MAX(timestamp) m FROM traffic")["m"] or 0
    alert_count = fetch_one("SELECT COUNT(*) c FROM alerts")["c"]
    critical_count = fetch_one("SELECT COUNT(*) c FROM alerts WHERE confidence_percent >= 90")["c"]
    anomalous_hosts = fetch_one("SELECT COUNT(DISTINCT src_ip) c FROM alerts")["c"]
    avg_latency = fetch_one("SELECT AVG(detection_latency_sec) a FROM alerts")["a"] or 0
    ja3_count = fetch_one("SELECT COUNT(*) c FROM ja3_feed")["c"]
    ml_count = fetch_one("SELECT COUNT(*) c FROM ml_predictions")["c"]
    anomaly_rate = (anomalous_hosts / active_hosts * 100) if active_hosts else 0
    return {
        "packets_analyzed": packet_count,
        "active_hosts": active_hosts,
        "session_length_sec": session_length,
        "threats_detected": alert_count,
        "critical_threats": critical_count,
        "anomalous_hosts": anomalous_hosts,
        "anomaly_rate_percent": round(anomaly_rate, 1),
        "avg_detection_latency_sec": round(avg_latency, 2),
        "known_bad_ja3_tracked": ja3_count,
        "ml_predictions_stored": ml_count,
    }


# =====================================================================
# ALERTS
# =====================================================================
@app.get("/api/alerts", tags=["alerts"])
def get_alerts(
    category: Optional[str] = None,
    src_ip: Optional[str] = None,
    min_confidence: float = 0,
    since: float = 0,
    limit: int = Query(100, le=1000),
):
    q = "SELECT * FROM alerts WHERE confidence_percent >= %s AND created_at > %s"
    params = [min_confidence, since]
    if category:
        q += " AND category = %s"
        params.append(category)
    if src_ip:
        q += " AND src_ip = %s"
        params.append(src_ip)
    q += " ORDER BY created_at DESC LIMIT %s"
    params.append(limit)
    return fetch_all(q, params)


@app.get("/api/alerts/by-category", tags=["alerts"])
def alerts_by_category():
    return fetch_all("SELECT category, COUNT(*) as count FROM alerts GROUP BY category ORDER BY count DESC")


# =====================================================================
# TRAFFIC
# =====================================================================
@app.get("/api/traffic", tags=["traffic"])
def get_traffic(src_ip: Optional[str] = None, since: float = 0, limit: int = Query(100, le=20000)):
    q = "SELECT * FROM traffic WHERE timestamp > %s"
    params = [since]
    if src_ip:
        q += " AND src_ip = %s"
        params.append(src_ip)
    q += " ORDER BY timestamp DESC LIMIT %s"
    params.append(limit)
    return fetch_all(q, params)


@app.get("/api/traffic/timeline", tags=["traffic"])
def traffic_timeline(bucket_seconds: float = Query(10.0, gt=0)):
    rows = fetch_all("SELECT timestamp FROM traffic")
    if not rows:
        return []
    df = pd.DataFrame([r["timestamp"] for r in rows], columns=["timestamp"])
    df["bucket"] = (df["timestamp"] // bucket_seconds) * bucket_seconds
    return df.groupby("bucket").size().reset_index(name="packets").to_dict(orient="records")


@app.get("/api/hosts/top", tags=["traffic"])
def top_hosts(limit: int = 8):
    rows = fetch_all(
        "SELECT src_ip, COUNT(*) as packet_count FROM traffic GROUP BY src_ip "
        "ORDER BY packet_count DESC LIMIT %s", (limit,),
    )
    flagged = {r["src_ip"] for r in fetch_all("SELECT DISTINCT src_ip FROM alerts")}
    return [{"src_ip": r["src_ip"], "packet_count": r["packet_count"], "flagged": r["src_ip"] in flagged} for r in rows]


@app.get("/api/ports/top", tags=["traffic"])
def top_ports(limit: int = 6):
    return fetch_all(
        "SELECT dst_port, COUNT(*) as count FROM traffic GROUP BY dst_port ORDER BY count DESC LIMIT %s", (limit,),
    )


# =====================================================================
# PIPELINE — now describes the ML models (the AI detection path), not
# rule-based time layers. "layers" key name kept for API compatibility
# with the dashboard, but every entry here is a trained model.
# =====================================================================
@app.get("/api/pipeline", tags=["stats"])
def pipeline():
    layers = [
        {"key": "Random Forest (main classifier)", "name": "Random Forest",
         "catches": "All 5 attack types \u2014 main decision-maker"},
        {"key": "Isolation Forest (anomaly detector)", "name": "Isolation Forest",
         "catches": "Unclassified anomalies \u2014 trained on normal traffic only"},
    ]
    out = []
    for l in layers:
        row = fetch_one(
            "SELECT COUNT(*) c, AVG(detection_latency_sec) a FROM alerts WHERE layer = %s", (l["key"],),
        )
        out.append({**l, "alert_count": row["c"], "avg_latency_sec": round(row["a"], 2) if row["a"] is not None else None})
    return {"layers": out}


# =====================================================================
# JA3 THREAT FEED
# =====================================================================
@app.get("/api/ja3-feed", tags=["ja3"])
def ja3_feed():
    feed = fetch_all("SELECT ja3, threat FROM ja3_feed")
    matched = {r["ja3"] for r in fetch_all("SELECT DISTINCT ja3 FROM alerts WHERE ja3 != ''")}
    return [{"ja3": r["ja3"], "threat": r["threat"], "matched": r["ja3"] in matched} for r in feed]


# =====================================================================
# GEOLOCATION
# =====================================================================
@app.get("/api/geo/{ip}", tags=["geo"])
def geo_lookup(ip: str):
    return geo_module.geolocate(ip)


# =====================================================================
# MACHINE LEARNING
# =====================================================================
@app.get("/api/ml/models", tags=["ml"])
def ml_models_info():
    """The 6 trained models and their held-out test accuracy — the
    honest numbers from train_models.py, not just a claim."""
    import json, os
    report_path = os.path.join("models", "training_report.json")
    if not os.path.exists(report_path):
        raise HTTPException(404, "No trained models found. Run train_models.py first.")
    with open(report_path) as f:
        return json.load(f)


@app.get("/api/ml/predict/{ip}", tags=["ml"])
def ml_predict_host(ip: str):
    """Runs all 5 predictive models (everything except the domain-only
    Naive Bayes) against one host's full traffic history, live."""
    rows = fetch_all("SELECT * FROM traffic WHERE src_ip = %s ORDER BY timestamp", (ip,))
    if not rows:
        raise HTTPException(404, f"No traffic found for {ip}")
    host_df = pd.DataFrame(rows)
    host_df["dns_query"] = host_df["dns_query"].fillna("")
    host_df["ja3"] = host_df["ja3"].fillna("")
    bad_ja3 = set(get_ja3_feed_dict().keys())
    try:
        return mm.predict_all(host_df, bad_ja3)
    except FileNotFoundError:
        raise HTTPException(404, "Models not trained yet. Run train_models.py first.")


@app.post("/api/ml/predict-domain", tags=["ml"])
def ml_predict_domain(body: DomainIn):
    """Naive Bayes: is this domain name real-looking or gibberish
    (DGA-style)? Try it with a real domain and a random string."""
    try:
        return mm.predict_domain_naive_bayes(body.domain)
    except FileNotFoundError:
        raise HTTPException(404, "Models not trained yet. Run train_models.py first.")


@app.get("/api/ml/predictions/{ip}", tags=["ml"])
def ml_predictions_for_host(ip: str):
    """Every individual model's verdict on this host, one row per
    model per alert event — the real content of the ml_predictions
    table, grouped by when they were recorded (so you get one clean
    'panel of 5 opinions' per detection, not everything smeared
    together)."""
    rows = fetch_all(
        "SELECT model_name, predicted_label, confidence, is_final_verdict, created_at FROM ml_predictions "
        "WHERE src_ip = %s ORDER BY created_at DESC, model_name", (ip,),
    )
    grouped = {}
    for r in rows:
        grouped.setdefault(r["created_at"], []).append({
            "model": r["model_name"], "predicted_label": r["predicted_label"],
            "confidence": None if r["confidence"] == -1 else r["confidence"],
            "is_final_verdict": bool(r["is_final_verdict"]),
        })
    return [{"created_at": k, "opinions": v} for k, v in sorted(grouped.items(), reverse=True)]


# =====================================================================
# LIVE INGESTION
# =====================================================================
@app.post("/api/ingest", tags=["ingest"])
def ingest(pkt: PacketIn):
    """Stores one new packet and re-runs the ML models (Random Forest +
    Isolation Forest) against that host's rolling history — this is the
    AI detection path: every alert below comes from a trained model's
    prediction, not a hand-written threshold rule. A real deployment
    would call this once per captured packet."""
    conn = db.get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO traffic (timestamp, src_ip, dst_ip, dst_port, protocol, packet_size, dns_query, ja3) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (pkt.timestamp, pkt.src_ip, pkt.dst_ip, pkt.dst_port, pkt.protocol,
                 pkt.packet_size, pkt.dns_query, pkt.ja3),
            )
        conn.commit()

        with conn.cursor() as cur:
            cur.execute(
                "SELECT timestamp, src_ip, dst_ip, dst_port, protocol, packet_size, dns_query, ja3 "
                "FROM traffic WHERE src_ip = %s ORDER BY timestamp", (pkt.src_ip,),
            )
            host_rows = cur.fetchall()
        host_df = pd.DataFrame(host_rows)

        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT category FROM alerts WHERE src_ip = %s", (pkt.src_ip,))
            already_alerted = {r["category"] for r in cur.fetchall()}

        ja3_feed_dict = get_ja3_feed_dict()
        first_seen = host_df["timestamp"].min()

        try:
            candidate_alerts = mld.detect_via_ml(host_df, pkt.src_ip, ja3_feed_dict, now=pkt.timestamp)
        except FileNotFoundError:
            raise HTTPException(503, "ML models not trained yet. Run train_models.py in the backend folder first.")

        new_alerts = []
        with conn.cursor() as cur:
            for a in candidate_alerts:
                if a["category"] in already_alerted:
                    continue

                # Once Random Forest confidently names a SPECIFIC category,
                # any earlier vague "Unclassified Anomaly" from Isolation
                # Forest for this same host is now stale information — we
                # know what it actually was, so remove it rather than leave
                # two seemingly-contradictory alerts sitting side by side.
                if a["model_used"] == "random_forest":
                    cur.execute(
                        "DELETE FROM alerts WHERE src_ip = %s AND category = 'Unclassified Anomaly'",
                        (pkt.src_ip,),
                    )
                    already_alerted.discard("Unclassified Anomaly")

                latency = max(0.0, a["timestamp"] - first_seen)
                alert_created_at = time.time()
                cur.execute(
                    "INSERT INTO alerts (timestamp, layer, category, src_ip, confidence_percent, "
                    "explanation, detection_latency_sec, decoded_bits, ja3, matched_threat, model_used, created_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (a["timestamp"], a["layer"], a["category"], pkt.src_ip, a["confidence_percent"],
                     a["explanation"], round(latency, 2), a.get("decoded_bits", ""),
                     a.get("ja3", ""), a.get("matched_threat", ""), a["model_used"], alert_created_at),
                )
                # store each of the 6 models' individual verdict as its own row —
                # this is what actually makes "which models caught this" a real,
                # queryable answer instead of a sentence buried in explanation text
                for op in a.get("model_opinions", []):
                    cur.execute(
                        "INSERT INTO ml_predictions (src_ip, model_name, predicted_label, confidence, "
                        "is_final_verdict, features_json, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        (pkt.src_ip, op["model"], op["predicted_label"],
                         op["confidence"] if op["confidence"] is not None else -1,
                         op.get("is_final_verdict", False), "", alert_created_at),
                    )
                new_alerts.append(a)
        conn.commit()

        return {
            "packet_stored": True, "host_packet_count": len(host_df),
            "new_alerts": new_alerts,
        }
    finally:
        conn.close()


@app.delete("/api/reset", tags=["meta"])
def reset():
    db.clear_all()
    return {"status": "cleared"}


# =====================================================================
# LIVE WEBSOCKET FEED
# =====================================================================
@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket, speed: float = 40.0):
    speed = max(1.0, min(speed, 500.0))
    await websocket.accept()
    try:
        rows = fetch_all("SELECT * FROM traffic ORDER BY timestamp")
        flagged_rows = fetch_all("SELECT src_ip, category FROM alerts GROUP BY src_ip, category")
        flagged = {r["src_ip"]: r["category"] for r in flagged_rows}

        last_t = 0.0
        for r in rows:
            gap = max(0.0, (r["timestamp"] - last_t) / speed)
            await asyncio.sleep(max(min(gap, 0.5), 0.001))
            last_t = r["timestamp"]
            status = flagged.get(r["src_ip"], "Normal")
            await websocket.send_json({
                "timestamp": r["timestamp"], "src_ip": r["src_ip"], "dst_ip": r["dst_ip"],
                "dst_port": r["dst_port"], "protocol": r["protocol"],
                "packet_size": r["packet_size"], "dns_query": r["dns_query"] or None,
                "status": status,
            })
        await websocket.close(code=1000)
    except WebSocketDisconnect:
        pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main_mysql:app", host="0.0.0.0", port=8000, reload=False)
