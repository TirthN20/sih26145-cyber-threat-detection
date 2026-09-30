"""
BACKEND API SERVER
====================================================
What this is, in plain English:

Until now, everything ran as standalone scripts reading/writing CSV
files. A real system needs a backend: a running service other programs
(a web dashboard, a mobile app, a SIEM integration) can talk to over
the network. This is that service, built with FastAPI.

  1. On startup, loads traffic_log.csv + ja3_threat_feed.json into a
     real SQLite database (backend/data.db) and runs all 5 detection
     layers — same logic as detector.py, refactored into detection.py
     so both the batch script and this live service agree with each
     other by construction, not by coincidence.
  2. Exposes that data as JSON over plain REST endpoints (GET
     /api/alerts, /api/stats, etc.) — try them all at /docs.
  3. POST /api/ingest accepts ONE new packet and re-runs detection
     against that host's rolling history immediately — genuine
     real-time capability, not just serving a static file.
  4. GET /ws/live pushes stored traffic over a WebSocket, paced out
     in real time (sped up), for an actual server-pushed live feed.
  5. /docs gives you free, interactive, point-and-click API
     documentation — open it in a browser, no coding needed, great to
     show judges directly.

HOW TO RUN THIS (see README.md for the full walkthrough):
    cd backend
    python3 seed.py              (once, or whenever traffic_log.csv changes)
    uvicorn main:app --reload
Then open http://127.0.0.1:8000/docs
"""

import asyncio
import hashlib
import time
from typing import Optional

import pandas as pd
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import database as db
import detection as det

app = FastAPI(
    title="PS 26145 — Unidirectional Threat Detector API",
    description=(
        "Backend for AI-based detection of cyber threats in unidirectional IP traffic. "
        "Five detection layers (instant JA3 signature match, flood/DoS, port scan, "
        "DNS tunneling, covert timing channel) running against a SQLite-backed store, "
        "with a real-time ingestion endpoint and a live WebSocket feed."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

db.init_db()


def get_ja3_feed_dict():
    conn = db.get_conn()
    rows = conn.execute("SELECT ja3, threat FROM ja3_feed").fetchall()
    conn.close()
    return {r["ja3"]: r["threat"] for r in rows}


def row_to_dict(row):
    return dict(row)


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


# =====================================================================
# META
# =====================================================================
@app.get("/", tags=["meta"])
def root():
    return {
        "project": "PS 26145 — Unidirectional Threat Detector",
        "docs": "/docs",
        "endpoints": [
            "GET /api/health", "GET /api/stats", "GET /api/alerts",
            "GET /api/alerts/by-category", "GET /api/traffic",
            "GET /api/traffic/timeline", "GET /api/hosts/top", "GET /api/ports/top",
            "GET /api/ja3-feed", "GET /api/geo/{ip}", "POST /api/ingest",
            "DELETE /api/reset", "WS /ws/live",
        ],
    }


@app.get("/api/health", tags=["meta"])
def health():
    conn = db.get_conn()
    packet_count = conn.execute("SELECT COUNT(*) c FROM traffic").fetchone()["c"]
    conn.close()
    return {"status": "ok", "time": time.time(), "packets_in_db": packet_count}


# =====================================================================
# STATS
# =====================================================================
@app.get("/api/stats", tags=["stats"])
def get_stats():
    conn = db.get_conn()
    packet_count = conn.execute("SELECT COUNT(*) c FROM traffic").fetchone()["c"]
    active_hosts = conn.execute("SELECT COUNT(DISTINCT src_ip) c FROM traffic").fetchone()["c"]
    session_length = conn.execute("SELECT MAX(timestamp) m FROM traffic").fetchone()["m"] or 0
    alert_count = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    critical_count = conn.execute("SELECT COUNT(*) c FROM alerts WHERE confidence_percent >= 90").fetchone()["c"]
    anomalous_hosts = conn.execute("SELECT COUNT(DISTINCT src_ip) c FROM alerts").fetchone()["c"]
    avg_latency = conn.execute("SELECT AVG(detection_latency_sec) a FROM alerts").fetchone()["a"] or 0
    ja3_count = conn.execute("SELECT COUNT(*) c FROM ja3_feed").fetchone()["c"]
    conn.close()
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
    }


# =====================================================================
# ALERTS
# =====================================================================
@app.get("/api/alerts", tags=["alerts"])
def get_alerts(
    category: Optional[str] = Query(None, description="Filter to one threat category"),
    src_ip: Optional[str] = Query(None, description="Filter to one source IP"),
    min_confidence: float = Query(0, description="Only alerts at or above this confidence %"),
    since: float = Query(0, description="Only alerts created after this unix time — for polling"),
    limit: int = Query(100, le=1000),
):
    """All alerts, newest first. Pass `since` back the last poll's max
    `created_at` to fetch only NEW alerts instead of re-fetching everything."""
    conn = db.get_conn()
    q = "SELECT * FROM alerts WHERE confidence_percent >= ? AND created_at > ?"
    params = [min_confidence, since]
    if category:
        q += " AND category = ?"
        params.append(category)
    if src_ip:
        q += " AND src_ip = ?"
        params.append(src_ip)
    q += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]


@app.get("/api/alerts/by-category", tags=["alerts"])
def alerts_by_category():
    conn = db.get_conn()
    rows = conn.execute(
        "SELECT category, COUNT(*) as count FROM alerts GROUP BY category ORDER BY count DESC"
    ).fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]


# =====================================================================
# TRAFFIC
# =====================================================================
@app.get("/api/traffic", tags=["traffic"])
def get_traffic(
    src_ip: Optional[str] = Query(None, description="Filter to one source IP"),
    since: float = Query(0, description="Only packets after this timestamp — for polling"),
    limit: int = Query(100, le=2000),
):
    conn = db.get_conn()
    q = "SELECT * FROM traffic WHERE timestamp > ?"
    params = [since]
    if src_ip:
        q += " AND src_ip = ?"
        params.append(src_ip)
    q += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]


@app.get("/api/traffic/timeline", tags=["traffic"])
def traffic_timeline(bucket_seconds: float = Query(10.0, gt=0)):
    """Packet counts bucketed by time — what the dashboard's
    'traffic & threats over time' chart is built from."""
    conn = db.get_conn()
    rows = conn.execute("SELECT timestamp FROM traffic").fetchall()
    conn.close()
    if not rows:
        return []
    df = pd.DataFrame([r["timestamp"] for r in rows], columns=["timestamp"])
    df["bucket"] = (df["timestamp"] // bucket_seconds) * bucket_seconds
    counts = df.groupby("bucket").size().reset_index(name="packets")
    return counts.to_dict(orient="records")


@app.get("/api/hosts/top", tags=["traffic"])
def top_hosts(limit: int = 8):
    conn = db.get_conn()
    rows = conn.execute(
        "SELECT src_ip, COUNT(*) as packet_count FROM traffic GROUP BY src_ip "
        "ORDER BY packet_count DESC LIMIT ?", (limit,),
    ).fetchall()
    flagged = {r["src_ip"] for r in conn.execute("SELECT DISTINCT src_ip FROM alerts").fetchall()}
    conn.close()
    return [{"src_ip": r["src_ip"], "packet_count": r["packet_count"], "flagged": r["src_ip"] in flagged} for r in rows]


@app.get("/api/ports/top", tags=["traffic"])
def top_ports(limit: int = 6):
    conn = db.get_conn()
    rows = conn.execute(
        "SELECT dst_port, COUNT(*) as count FROM traffic GROUP BY dst_port "
        "ORDER BY count DESC LIMIT ?", (limit,),
    ).fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]


# =====================================================================
# PIPELINE (per-layer counts + latency — what the pipeline strip shows)
# =====================================================================
@app.get("/api/pipeline", tags=["stats"])
def pipeline():
    layers = [
        {"key": "Layer 0 (instant, JA3 fingerprint)", "name": "Instant", "catches": "Malicious TLS fingerprints"},
        {"key": "Layer 1 (fast, 5s)", "name": "Fast", "catches": "Floods, DoS bursts"},
        {"key": "Layer 2 (medium, 30s)", "name": "Medium", "catches": "Port scans"},
        {"key": "Layer 3 (slow, DNS pattern)", "name": "Slow", "catches": "DNS tunneling, beaconing"},
        {"key": "Layer 4 (very slow, covert channel)", "name": "Very slow", "catches": "Covert timing channels"},
    ]
    conn = db.get_conn()
    out = []
    for l in layers:
        row = conn.execute(
            "SELECT COUNT(*) c, AVG(detection_latency_sec) a FROM alerts WHERE layer = ?", (l["key"],),
        ).fetchone()
        out.append({**l, "alert_count": row["c"], "avg_latency_sec": round(row["a"], 2) if row["a"] is not None else None})
    conn.close()
    return {"layers": out}


# =====================================================================
# JA3 THREAT FEED
# =====================================================================
@app.get("/api/ja3-feed", tags=["ja3"])
def ja3_feed():
    conn = db.get_conn()
    feed = conn.execute("SELECT ja3, threat FROM ja3_feed").fetchall()
    matched = {r["ja3"] for r in conn.execute("SELECT DISTINCT ja3 FROM alerts WHERE ja3 != ''").fetchall()}
    conn.close()
    return [{"ja3": r["ja3"], "threat": r["threat"], "matched": r["ja3"] in matched} for r in feed]


# =====================================================================
# GEOLOCATION (simulated — see backend/geo.py for why)
# =====================================================================
import geo as geo_module


@app.get("/api/geo/{ip}", tags=["geo"])
def geo_lookup(ip: str):
    return geo_module.geolocate(ip)


# =====================================================================
# LIVE INGESTION — real-time capability
# =====================================================================
@app.post("/api/ingest", tags=["ingest"])
def ingest(pkt: PacketIn):
    """Accepts ONE new packet, stores it, then re-runs all 5 detection
    checks against that host's full rolling history (old + new packets
    together), using the exact same functions the historical data was
    seeded with. Any genuinely NEW alert (a category not already raised
    for this host) is saved and returned — this is what a real
    deployment would call once per captured packet from a live tap."""
    conn = db.get_conn()
    conn.execute(
        "INSERT INTO traffic (timestamp, src_ip, dst_ip, dst_port, protocol, packet_size, dns_query, ja3) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (pkt.timestamp, pkt.src_ip, pkt.dst_ip, pkt.dst_port, pkt.protocol,
         pkt.packet_size, pkt.dns_query, pkt.ja3),
    )
    conn.commit()

    host_rows = conn.execute(
        "SELECT timestamp, src_ip, dst_ip, dst_port, protocol, packet_size, dns_query, ja3 "
        "FROM traffic WHERE src_ip = ? ORDER BY timestamp", (pkt.src_ip,),
    ).fetchall()
    host_df = pd.DataFrame([dict(r) for r in host_rows])

    already_alerted = {
        r["category"] for r in conn.execute(
            "SELECT DISTINCT category FROM alerts WHERE src_ip = ?", (pkt.src_ip,)
        ).fetchall()
    }

    ja3_feed_dict = get_ja3_feed_dict()
    first_seen = host_df["timestamp"].min()
    candidate_alerts = det.run_all_checks(host_df, pkt.src_ip, ja3_feed_dict, now=pkt.timestamp)

    new_alerts = []
    for a in candidate_alerts:
        if a["category"] in already_alerted:
            continue
        latency = max(0.0, a["timestamp"] - first_seen)
        conn.execute(
            "INSERT INTO alerts (timestamp, layer, category, src_ip, confidence_percent, "
            "explanation, detection_latency_sec, decoded_bits, ja3, matched_threat, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (a["timestamp"], a["layer"], a["category"], a["src_ip"], a["confidence_percent"],
             a["explanation"], round(latency, 2), a.get("decoded_bits", ""),
             a.get("ja3", ""), a.get("matched_threat", ""), time.time()),
        )
        new_alerts.append(a)
    conn.commit()
    conn.close()

    return {"packet_stored": True, "host_packet_count": len(host_df), "new_alerts": new_alerts}


@app.delete("/api/reset", tags=["meta"])
def reset():
    """Wipes traffic + alerts (keeps the JA3 feed) — handy for demoing
    /api/ingest from a clean slate. Run seed.py again afterward to restore
    the historical demo data."""
    db.clear_all()
    return {"status": "cleared"}


# =====================================================================
# LIVE WEBSOCKET FEED — genuine server-pushed streaming, not client-side
# replay. Streams whatever is currently in the database, in timestamp
# order, paced out in real time (sped up by `speed`x).
# =====================================================================
@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket, speed: float = 40.0):
    """Try it from a browser console once the server is running:
        const ws = new WebSocket("ws://127.0.0.1:8000/ws/live?speed=60");
        ws.onmessage = (e) => console.log(JSON.parse(e.data));
    """
    speed = max(1.0, min(speed, 500.0))
    await websocket.accept()
    try:
        conn = db.get_conn()
        rows = conn.execute("SELECT * FROM traffic ORDER BY timestamp").fetchall()
        flagged = {r["src_ip"]: r["category"] for r in conn.execute(
            "SELECT src_ip, category FROM alerts GROUP BY src_ip"
        ).fetchall()}
        conn.close()

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
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
