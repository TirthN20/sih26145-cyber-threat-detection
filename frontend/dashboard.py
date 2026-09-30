"""
STEP 3: VISUAL DASHBOARD (what you actually show the judges)
====================================================
Turns traffic_log.csv + alerts.csv + ja3_threat_feed.json into a full,
live web page. Runs entirely on your own laptop. See README.md.
"""

import streamlit as st
import pandas as pd
import numpy as np
import altair as alt
import json
import time

st.set_page_config(
    page_title="PS 26145 — Unidirectional Threat Detector",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# =====================================================================
# DESIGN SYSTEM
# =====================================================================
BG_DEEP, BG_PANEL, BG_PANEL_ALT = "#0A1120", "#111B2E", "#16233A"
BORDER = "#223151"
FLOW = "#38BDF8"
SAFE = "#34D399"
WARN = "#FBBF24"
CRITICAL = "#FB7185"
INFO = "#A78BFA"
TEXT_MAIN, TEXT_MUTED = "#EAF0FB", "#7C8AA5"

CATEGORY_COLORS = {
    "Flood / DoS": CRITICAL,
    "Port Scan / Reconnaissance": WARN,
    "DNS Tunneling / C2 Beaconing": INFO,
    "Covert Timing Channel (hidden data exfiltration)": FLOW,
    "Encrypted C2 (malicious TLS fingerprint)": "#2DD4BF",
}
DEFAULT_CAT_COLOR = TEXT_MUTED

CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root {{
    --bg-deep: {BG_DEEP}; --bg-panel: {BG_PANEL}; --bg-panel-alt: {BG_PANEL_ALT};
    --border: {BORDER}; --flow: {FLOW}; --safe: {SAFE}; --warn: {WARN};
    --critical: {CRITICAL}; --info: {INFO};
    --text-main: {TEXT_MAIN}; --text-muted: {TEXT_MUTED};
}}

.stApp {{ background: var(--bg-deep); color: var(--text-main); }}
h1, h2, h3, h4 {{ font-family: 'Space Grotesk', sans-serif !important; }}
body, .stMarkdown p, .stMarkdown li, div, span {{ font-family: 'IBM Plex Mono', monospace; }}
#MainMenu, footer, header {{visibility: hidden;}}

/* FULL WIDTH — fill the screen instead of a narrow centered column */
.block-container {{ max-width: 100% !important; padding: 2rem 2.5rem 3rem 2.5rem; }}
@media (min-width: 1900px) {{ .block-container {{ padding: 2rem 4rem 3rem 4rem; }} }}

/* ---------------- HERO ---------------- */
.hero {{
    padding: 30px 36px; border: 1px solid var(--border); border-radius: 10px;
    background: linear-gradient(135deg, var(--bg-panel) 0%, var(--bg-panel-alt) 100%);
    margin-bottom: 22px; overflow: hidden;
}}
.hero-eyebrow {{ color: var(--flow); font-size: 13px; margin-bottom: 6px; }}
.hero-title {{ font-family: 'Space Grotesk', sans-serif; font-size: 32px; font-weight: 700; margin: 0 0 8px 0; line-height: 1.25; }}
.hero-sub {{ color: var(--text-muted); font-size: 14px; max-width: 720px; line-height: 1.6; margin-bottom: 18px; }}
.flow-track {{
    position: relative; height: 26px; border-radius: 6px; overflow: hidden; margin-bottom: 4px;
    background: repeating-linear-gradient(90deg, var(--bg-deep) 0px, var(--bg-deep) 8px, #1E5477 8px, #1E5477 10px);
}}
.flow-dot {{ position: absolute; top: 4px; width: 18px; height: 18px; border-radius: 50%; background: var(--flow);
    box-shadow: 0 0 12px 2px var(--flow); animation: flow-move 3.2s linear infinite; }}
.flow-dot.d2 {{ animation-delay: 1.1s; opacity: 0.7; }}
.flow-dot.d3 {{ animation-delay: 2.2s; opacity: 0.45; }}
@keyframes flow-move {{ from {{ left: -20px; }} to {{ left: 100%; }} }}
.flow-caption {{ font-size: 11px; color: var(--text-muted); display: flex; justify-content: space-between; }}

/* ---------------- STAT ROWS ---------------- */
.stat-box {{ border: 1px solid var(--border); background: var(--bg-panel); border-radius: 10px; padding: 15px 17px; }}
.stat-box.accent {{ border-color: #33445F; background: var(--bg-panel-alt); }}
.stat-num {{ font-family: 'Space Grotesk', sans-serif; font-size: 26px; font-weight: 700; }}
.stat-label {{ font-size: 11.5px; color: var(--text-muted); margin-top: 2px; }}
.row-caption {{ font-size: 11px; color: var(--text-muted); margin: 18px 0 6px 2px; }}

/* ---------------- PIPELINE ---------------- */
.pipeline-wrap {{ display: flex; gap: 6px; margin: 6px 0 26px 0; }}
.pipe-node {{ flex: 1; border: 1px solid var(--border); border-radius: 10px; padding: 14px 15px; background: var(--bg-panel); }}
.pipe-node.hot {{ border-color: var(--flow); background: var(--bg-panel-alt); }}
.pipe-num {{ font-family: 'Space Grotesk', sans-serif; font-size: 12px; color: var(--flow); margin-bottom: 6px; }}
.pipe-name {{ font-weight: 600; font-size: 13.5px; }}
.pipe-window {{ font-size: 10.5px; color: var(--text-muted); margin: 2px 0 8px 0; }}
.pipe-catches {{ font-size: 10.5px; color: var(--text-muted); line-height: 1.5; }}
.pipe-count {{ margin-top: 10px; font-size: 19px; font-weight: 700; color: var(--flow); font-family: 'Space Grotesk', sans-serif; }}
.pipe-arrow {{ display: flex; align-items: center; justify-content: center; color: var(--border); font-size: 16px; width: 14px; }}

/* ---------------- ALERT CARDS (now collapsible <details>/<summary>) ---------------- */
.alert-card {{ border: 1px solid var(--border); background: var(--bg-panel); border-left: 4px solid var(--warn);
    border-radius: 8px; margin-bottom: 10px; overflow: hidden; }}
.alert-card.sev-critical {{ border-left-color: var(--critical); }}
.alert-card.sev-medium {{ border-left-color: var(--warn); }}
.alert-card.sev-low {{ border-left-color: var(--flow); }}
.alert-summary {{ display: flex; align-items: center; gap: 14px; padding: 14px 18px; cursor: pointer; list-style: none; }}
.alert-summary::-webkit-details-marker {{ display: none; }}
.alert-summary::marker {{ content: ''; }}
.alert-summary-text {{ flex: 1; min-width: 0; }}
.alert-chevron {{ color: var(--text-muted); font-size: 13px; transition: transform 0.15s ease; flex-shrink: 0; }}
.alert-card[open] .alert-chevron {{ transform: rotate(90deg); }}
.alert-details {{ padding: 0 18px 16px 18px; }}
.alert-top {{ display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px; }}
.alert-category {{ font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 15px; }}
.alert-conf {{ font-size: 12.5px; color: var(--text-muted); text-align: right; }}
.alert-layer {{ font-size: 11px; color: var(--flow); margin-top: 2px; }}
.alert-explain {{ font-size: 13px; color: var(--text-muted); line-height: 1.55; }}
.alert-meta {{ font-size: 11px; color: var(--text-muted); margin-top: 8px; }}
.alert-meta code {{ color: var(--text-main); background: var(--bg-panel-alt); padding: 1px 5px; border-radius: 4px; }}
.latency-tag {{ display: inline-block; font-size: 10px; padding: 1px 7px; border-radius: 10px; background: rgba(56,189,248,0.12); color: var(--flow); margin-left: 6px; }}
.evidence-wrap {{ margin: 10px 0; }}

/* ---------------- DECODED SIGNAL STRIP (covert channel) ---------------- */
.decoded-wrap {{ margin-top: 12px; padding-top: 10px; border-top: 1px dashed var(--border); }}
.decoded-label {{ font-size: 10.5px; color: var(--text-muted); margin-bottom: 6px; }}
.decoded-track {{ display: flex; align-items: flex-end; gap: 2px; height: 22px; }}
.decoded-bar {{ background: var(--flow); border-radius: 1px; }}
.decoded-bar.one {{ background: var(--critical); }}
.decoded-bits-text {{ font-size: 10px; color: var(--text-muted); margin-top: 6px; letter-spacing: 1px; word-break: break-all; }}

/* ---------------- CATEGORY BARS ---------------- */
.cat-row {{ margin-bottom: 12px; }}
.cat-row-top {{ display: flex; justify-content: space-between; font-size: 12.5px; margin-bottom: 4px; }}
.cat-name {{ display: flex; align-items: center; gap: 7px; }}
.cat-dot {{ width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex-shrink: 0; }}
.cat-count {{ color: var(--text-muted); }}
.cat-track {{ height: 8px; background: var(--bg-panel-alt); border-radius: 4px; overflow: hidden; }}
.cat-fill {{ height: 100%; border-radius: 4px; }}

/* ---------------- ACTIVE HOSTS ---------------- */
.host-row {{ display: flex; justify-content: space-between; align-items: center; padding: 7px 0;
    border-bottom: 1px solid var(--border); font-size: 12px; }}
.host-row:last-child {{ border-bottom: none; }}
.host-count {{ color: var(--text-muted); }}
.pill {{ font-size: 9.5px; padding: 2px 8px; border-radius: 20px; font-weight: 600; white-space: nowrap; }}
.pill-flagged {{ background: rgba(251,113,133,0.15); color: var(--critical); }}
.pill-normal {{ background: rgba(52,211,153,0.12); color: var(--safe); }}

/* ---------------- JA3 FEED ---------------- */
.ja3-row {{ padding: 9px 0; border-bottom: 1px solid var(--border); }}
.ja3-row:last-child {{ border-bottom: none; }}
.ja3-top {{ display: flex; justify-content: space-between; align-items: center; }}
.ja3-hash {{ font-size: 11px; color: var(--text-muted); }}
.ja3-threat {{ font-size: 12.5px; margin-top: 2px; }}

/* ---------------- LIVE FEED (div-based rows: blink + click-to-expand) ---------------- */
.flow-header, .flow-row {{
    display: grid; grid-template-columns: 68px 122px 108px 118px 52px 52px 52px 1fr 108px;
    gap: 10px; align-items: center; padding: 7px 8px; font-size: 12px;
}}
.flow-header {{ color: var(--text-muted); font-size: 10.5px; border-bottom: 1px solid var(--border);
    position: sticky; top: 0; background: var(--bg-panel); }}
.flow-row {{ border-bottom: 1px solid #17223A; color: var(--text-main); border-left: 2px solid transparent; }}
.flow-toggle {{ display: none; }}
.flow-row.flagged {{ cursor: pointer; border-left: 2px solid var(--critical);
    background: rgba(251,113,133,0.06); animation: flow-blink 1.6s ease-in-out infinite; }}
@keyframes flow-blink {{
    0%, 100% {{ background: rgba(251,113,133,0.06); }}
    50% {{ background: rgba(251,113,133,0.22); }}
}}
.blink-dot {{ display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--critical);
    margin-right: 5px; animation: dot-blink 1.1s ease-in-out infinite; }}
@keyframes dot-blink {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.25; }} }}
.flow-detail {{ display: none; padding: 10px 16px 14px 16px; font-size: 12px; color: var(--text-muted);
    background: var(--bg-panel-alt); border-left: 2px solid var(--critical); border-radius: 0 0 6px 6px; }}
.flow-toggle:checked ~ .flow-detail {{ display: block; }}
.status-pill {{ font-size: 10px; padding: 2px 8px; border-radius: 20px; font-weight: 600; width: fit-content; }}

/* ---------------- LIVE FEED STATS BAR ---------------- */
.livebar {{ display: flex; gap: 22px; align-items: center; padding: 10px 16px; margin-bottom: 10px;
    border: 1px solid var(--border); border-radius: 8px; background: var(--bg-panel); font-size: 12.5px; color: var(--text-muted); }}
.livebar b {{ color: var(--text-main); font-family: 'Space Grotesk', sans-serif; }}
.livebar-muted {{ margin-left: auto; font-size: 11px; }}

/* ---------------- GEO CHIP (hover for city / ISP / ASN) ---------------- */
.geo-chip {{ position: relative; cursor: help; border-bottom: 1px dotted var(--text-muted); display: inline-block; }}
.geo-sim-tag {{ font-size: 8.5px; color: var(--text-muted); border: 1px solid var(--border); border-radius: 3px; padding: 0 3px; margin-left: 4px; vertical-align: middle; }}
.geo-popover {{
    display: none; position: absolute; bottom: 130%; left: 50%; transform: translateX(-50%);
    background: var(--bg-panel-alt); border: 1px solid var(--border); border-radius: 8px;
    padding: 8px 12px; font-size: 11px; white-space: nowrap; z-index: 50;
    box-shadow: 0 4px 16px rgba(0,0,0,0.4);
}}
.geo-popover div {{ margin: 2px 0; color: var(--text-main); }}
.geo-popover b {{ color: var(--text-muted); font-weight: 500; display: inline-block; width: 32px; }}
.geo-chip:hover .geo-popover {{ display: block; }}

/* ---------------- SECTION LABELS ---------------- */
.section-label {{ font-family: 'Space Grotesk', sans-serif; font-size: 16px; font-weight: 700; margin: 6px 0 12px 0; }}
.section-hint {{ font-size: 12px; color: var(--text-muted); margin-top: -8px; margin-bottom: 14px; }}
.panel {{ border: 1px solid var(--border); background: var(--bg-panel); border-radius: 10px; padding: 18px 20px; height: 100%; }}
[data-testid="stMetricValue"] {{ font-family: 'Space Grotesk', sans-serif; color: var(--flow); }}
.stButton button {{ background: var(--bg-panel-alt) !important; color: var(--text-main) !important; border: 1px solid var(--flow) !important; border-radius: 8px !important; font-family: 'IBM Plex Mono', monospace !important; }}
.stButton button:hover {{ background: var(--flow) !important; color: var(--bg-deep) !important; }}
.live-dot {{ display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--safe); margin-right:6px; animation: pulse 1.4s infinite; }}
@keyframes pulse {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:0.3; }} }}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

# =====================================================================
# LOAD DATA — from the MySQL backend's API (prototype v3: one real,
# unified system instead of the dashboard quietly reading its own CSV
# copies behind the backend's back). If the backend isn't running,
# this fails loudly with instructions instead of a cryptic error.
# =====================================================================
import requests

API_BASE = "http://127.0.0.1:8000"


@st.cache_data(ttl=10, show_spinner=False)
def fetch_json(path, params=None):
    r = requests.get(f"{API_BASE}{path}", params=params, timeout=5)
    r.raise_for_status()
    return r.json()


try:
    traffic_raw = fetch_json("/api/traffic", {"limit": 20000})
    alerts_raw = fetch_json("/api/alerts", {"limit": 1000})
    ja3_feed = fetch_json("/api/ja3-feed")
except requests.exceptions.ConnectionError:
    st.error(
        f"Can't reach the backend at {API_BASE}. Open a terminal in the "
        f"`backend` folder and run:\n\n`uvicorn main_mysql:app --reload`\n\n"
        f"then reload this page."
    )
    st.stop()
except requests.exceptions.RequestException as e:
    st.error(f"The backend responded with an error: {e}")
    st.stop()

if not traffic_raw:
    st.error(
        "The backend is running but has no data yet. In the `backend` "
        "folder, run:\n\n`python seed_mysql.py`\n\nthen reload this page."
    )
    st.stop()

traffic = pd.DataFrame(traffic_raw).sort_values("timestamp").reset_index(drop=True)
alert_cols = ["timestamp", "layer", "category", "src_ip", "confidence_percent", "explanation",
              "detection_latency_sec", "decoded_bits", "ja3", "matched_threat", "model_used", "created_at"]
alerts = pd.DataFrame(alerts_raw, columns=alert_cols) if alerts_raw else pd.DataFrame(columns=alert_cols)
if len(alerts):
    alerts = alerts.sort_values("timestamp").reset_index(drop=True)

traffic["dns_query"] = traffic["dns_query"].fillna("")
traffic["ja3"] = traffic["ja3"].fillna("")
alerts["decoded_bits"] = alerts["decoded_bits"].fillna("").astype(str)
alerts["detection_latency_sec"] = alerts["detection_latency_sec"].fillna(0)
alerts["ja3"] = alerts["ja3"].fillna("").astype(str)
flagged_ips = set(alerts["src_ip"].unique())
ip_to_category = alerts.drop_duplicates("src_ip").set_index("src_ip")["category"].to_dict()

LAYER_META = [
    {"key": "Layer 0 (instant, JA3 fingerprint)", "num": "00", "name": "Instant", "window": "Signature match", "catches": "Malicious TLS fingerprints"},
    {"key": "Layer 1 (fast, 5s)", "num": "01", "name": "Fast", "window": "5-second window", "catches": "Floods, DoS bursts"},
    {"key": "Layer 2 (medium, 30s)", "num": "02", "name": "Medium", "window": "30-second window", "catches": "Port scans"},
    {"key": "Layer 3 (slow, DNS pattern)", "num": "03", "name": "Slow", "window": "Pattern over time", "catches": "DNS tunneling, beaconing"},
    {"key": "Layer 4 (very slow, covert channel)", "num": "04", "name": "Very slow", "window": "Full session", "catches": "Covert timing channels"},
    {"key": "Layer 5 (catch-all, anomaly detector)", "num": "05", "name": "Catch-all", "window": "Isolation Forest", "catches": "Unclassified anomalies"},
]

def severity(pct):
    if pct >= 90: return "sev-critical"
    if pct >= 70: return "sev-medium"
    return "sev-low"

def status_pill(ip):
    if ip in flagged_ips:
        cat = ip_to_category.get(ip, "Flagged")
        short = cat.split(" (")[0].split(" /")[0]
        return f'<span class="status-pill" style="background:rgba(251,113,133,0.15);color:{CRITICAL}">{short}</span>'
    return f'<span class="status-pill" style="background:rgba(52,211,153,0.12);color:{SAFE}">Normal</span>'

# =====================================================================
# GEOLOCATION (country / city / ISP / ASN per source IP)
# =====================================================================
# IMPORTANT, READ THIS: the demo traffic uses 10.x.x.x (private LAN range)
# for normal hosts and 203.0.113.x / 198.51.100.x for attackers. The
# second pair are IANA-reserved "documentation" ranges (RFC 5737) —
# deliberately fake, non-routable addresses, used so this demo never
# points at a real address. A real geolocation API (ipinfo.io, ip-api.com,
# MaxMind GeoLite2, etc.) would return NOTHING for any of these, which
# would make the dashboard look broken rather than realistic.
#
# So: this function SIMULATES geolocation — same idea as the synthetic
# JA3 feed — deterministically (the same IP always gets the same fake
# location, so it's consistent across reruns), clearly labelled as
# simulated in the UI. A drop-in REAL version (using the free ip-api.com
# endpoint, no key needed) is provided right below it — if you swap in
# real captured traffic with real public IPs later, call that one instead.
import hashlib

_SIMULATED_GEO_POOL = [
    ("Australia", "Sydney", "Southern Cross Broadband", "AS64512"),
    ("Brazil", "Sao Paulo", "Atlantico Fiber Networks", "AS64513"),
    ("Canada", "Toronto", "Northline Communications", "AS64514"),
    ("France", "Paris", "Meridien Data Systems", "AS64515"),
    ("Germany", "Frankfurt", "Kontinental Hosting", "AS64516"),
    ("India", "Mumbai", "Konnect Broadband", "AS64517"),
    ("Ireland", "Dublin", "Emerald Cloud Services", "AS64518"),
    ("Japan", "Tokyo", "Sakura Network Systems", "AS64519"),
    ("Kenya", "Nairobi", "Savanna Link Telecom", "AS64520"),
    ("Netherlands", "Amsterdam", "Zeeland Internet Exchange", "AS64521"),
    ("Poland", "Warsaw", "Wisla Data Networks", "AS64522"),
    ("Singapore", "Singapore", "Straits Fiber Group", "AS64523"),
    ("South Africa", "Johannesburg", "Highveld Connect", "AS64524"),
    ("South Korea", "Seoul", "Hangang Broadband", "AS64525"),
    ("United Kingdom", "London", "Thamesline Networks", "AS64526"),
    ("United States", "Ashburn", "Beltway Cloud Hosting", "AS64527"),
]

def geolocate_simulated(ip):
    """Deterministic fake geolocation for demo (non-routable) IPs."""
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
        return {"country": "Internal", "city": "Private network", "isp": "\u2014", "asn": "\u2014", "simulated": False}
    idx = int(hashlib.md5(ip.encode()).hexdigest(), 16) % len(_SIMULATED_GEO_POOL)
    country, city, isp, asn = _SIMULATED_GEO_POOL[idx]
    return {"country": country, "city": city, "isp": isp, "asn": asn, "simulated": True}

def geolocate_real(ip):
    """DROP-IN REPLACEMENT for real, publicly-routable IPs (e.g. if you
    swap in CIDDS-001 or a live capture). Uses ip-api.com's free JSON
    endpoint (no API key, ~45 req/min limit) — cache results, don't call
    this in a tight loop over thousands of rows.
        import requests
        def geolocate_real(ip):
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
            if r.get("status") != "success":
                return {"country": "Unknown", "city": "\u2014", "isp": "\u2014", "asn": "\u2014"}
            return {"country": r["country"], "city": r["city"], "isp": r["isp"], "asn": r.get("as", "\u2014")}
    Left as a docstring, not live code, so this project stays fully
    offline-capable — wire it in only once you have real IPs to look up.
    """
    raise NotImplementedError("See docstring — swap this in only for real, public IPs.")

_geo_cache = {}
def geo(ip):
    if ip not in _geo_cache:
        _geo_cache[ip] = geolocate_simulated(ip)
    return _geo_cache[ip]

def geo_chip(ip):
    g = geo(ip)
    tag = "" if g["country"] == "Internal" else '<span class="geo-sim-tag">sim</span>'
    return f'''<span class="geo-chip">{g["country"]}{tag}
        <div class="geo-popover">
            <div><b>City</b> {g["city"]}</div>
            <div><b>ISP</b> {g["isp"]}</div>
            <div><b>ASN</b> {g["asn"]}</div>
        </div></span>'''


# =====================================================================
# PAGE: OVERVIEW (everything above the live feed, unchanged, just moved
# into a function so it can be one of two navigable pages)
# =====================================================================
def render_overview_page():

    # HERO
    # =====================================================================
    st.markdown("""
    <div class="hero">
        <div class="hero-eyebrow">PS 26145 &middot; NTRO</div>
        <div class="hero-title">Watching a network you can only see one side of.</div>
        <div class="hero-sub">
            This system analyzes traffic captured in a single direction only —
            no return packets, no handshakes, no responses — and still finds
            five distinct classes of threat, from obvious floods to malicious
            encrypted fingerprints to hidden data smuggled in packet timing.
        </div>
        <div class="flow-track">
            <div class="flow-dot d1"></div><div class="flow-dot d2"></div><div class="flow-dot d3"></div>
        </div>
        <div class="flow-caption">
            <span>source</span><span>traffic observed in one direction only &#8594;</span><span>monitoring point</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if st.button("▶  View live traffic feed", key="goto_live_feed_top", use_container_width=False):
        st.switch_page(page_live_feed)
    st.markdown("<div style='height:18px'></div>", unsafe_allow_html=True)

    _render_overview_live_section()


@st.fragment(run_every=12)
def _render_overview_live_section():
    # Re-fetches fresh data every 12 seconds (bounded by fetch_json's own
    # 10s cache, so this genuinely reflects new packets/alerts without
    # a manual browser refresh) and rebuilds these as LOCAL variables,
    # shadowing the module-level ones from first page load — everything
    # below already reads these same names, so no other changes needed.
    traffic_raw2 = fetch_json("/api/traffic", {"limit": 20000})
    alerts_raw2 = fetch_json("/api/alerts", {"limit": 1000})
    ja3_feed = fetch_json("/api/ja3-feed")

    traffic = pd.DataFrame(traffic_raw2).sort_values("timestamp").reset_index(drop=True)
    alert_cols2 = ["timestamp", "layer", "category", "src_ip", "confidence_percent", "explanation",
                   "detection_latency_sec", "decoded_bits", "ja3", "matched_threat", "model_used", "created_at"]
    alerts = pd.DataFrame(alerts_raw2, columns=alert_cols2) if alerts_raw2 else pd.DataFrame(columns=alert_cols2)
    if len(alerts):
        alerts = alerts.sort_values("timestamp").reset_index(drop=True)

    traffic["dns_query"] = traffic["dns_query"].fillna("")
    traffic["ja3"] = traffic["ja3"].fillna("")
    alerts["decoded_bits"] = alerts["decoded_bits"].fillna("").astype(str)
    alerts["detection_latency_sec"] = alerts["detection_latency_sec"].fillna(0)
    alerts["ja3"] = alerts["ja3"].fillna("").astype(str)
    flagged_ips = set(alerts["src_ip"].unique())
    ip_to_category = alerts.drop_duplicates("src_ip").set_index("src_ip")["category"].to_dict()

    # =====================================================================
    # STAT ROWS
    # =====================================================================
    active_hosts = traffic["src_ip"].nunique()
    critical_threats = len(alerts[alerts["confidence_percent"] >= 90])
    anomalous_hosts = len(flagged_ips)
    anomaly_rate = (anomalous_hosts / active_hosts * 100) if active_hosts else 0
    avg_latency = alerts["detection_latency_sec"].mean() if len(alerts) else 0

    r1 = st.columns(4)
    for col, (num, label) in zip(r1, [
        (f"{len(traffic):,}", "packets analyzed"),
        (f"{active_hosts}", "active hosts"),
        (f"{traffic['timestamp'].max():.0f}s", "session length"),
        (f"{len(alerts)}", "threats detected"),
    ]):
        col.markdown(f'<div class="stat-box"><div class="stat-num">{num}</div><div class="stat-label">{label}</div></div>', unsafe_allow_html=True)

    st.markdown('<div class="row-caption">security posture</div>', unsafe_allow_html=True)
    r2 = st.columns(4)
    for col, (num, label, color) in zip(r2, [
        (f"{critical_threats}", "critical threats (&ge;90% confidence)", CRITICAL),
        (f"{anomalous_hosts} / {active_hosts}", f"anomalous flows ({anomaly_rate:.0f}%)", WARN),
        (f"{avg_latency:.1f}s", "avg detection latency", FLOW),
        (f"{len(ja3_feed)}", "known-bad TLS fingerprints tracked", INFO),
    ]):
        col.markdown(f'<div class="stat-box accent"><div class="stat-num" style="color:{color}">{num}</div><div class="stat-label">{label}</div></div>', unsafe_allow_html=True)

    st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)

    # =====================================================================
    # THREAT LEVEL GAUGE — the one thing anyone, technical or not, can read
    # at a glance. Score is a simple, transparent blend of how many hosts
    # are misbehaving and how confident we are about the worst of them.
    # =====================================================================
    threat_score = min(100, anomaly_rate * 0.55 + critical_threats * 7)
    if threat_score < 25:
        zone, zone_color, zone_msg = "Low", SAFE, "Nothing significant standing out right now."
    elif threat_score < 50:
        zone, zone_color, zone_msg = "Guarded", FLOW, "A few things worth a look, nothing urgent."
    elif threat_score < 75:
        zone, zone_color, zone_msg = "Elevated", WARN, "Multiple active threats — worth investigating now."
    else:
        zone, zone_color, zone_msg = "Severe", CRITICAL, "Multiple high-confidence threats active on the network."

    st.markdown(f"""
    <div class="panel" style="margin-bottom:26px;">
        <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:10px;">
            <div>
                <div class="section-label" style="margin:0;">Network threat level</div>
                <div class="section-hint" style="margin:2px 0 0 0;">{zone_msg}</div>
            </div>
            <div style="font-family:'Space Grotesk',sans-serif; font-size:22px; font-weight:700; color:{zone_color};">{zone}</div>
        </div>
        <div style="position:relative; height:10px; border-radius:5px;
                    background: linear-gradient(90deg, {SAFE} 0%, {FLOW} 33%, {WARN} 66%, {CRITICAL} 100%);">
            <div style="position:absolute; top:-5px; left:calc({threat_score}% - 2px); width:4px; height:20px;
                        background:{TEXT_MAIN}; border-radius:2px; box-shadow:0 0 6px rgba(255,255,255,0.6);"></div>
        </div>
        <div style="display:flex; justify-content:space-between; font-size:10px; color:{TEXT_MUTED}; margin-top:6px;">
            <span>low</span><span>guarded</span><span>elevated</span><span>severe</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # =====================================================================
    # COMPOSITION DONUTS — anomalous vs normal hosts, alert severity mix,
    # and protocol mix. A donut with a big center number reads instantly,
    # which is exactly what "critical threats" and "anomalous flows" need.
    # =====================================================================
    def donut(data, labels, colors, center_num, center_label):
        """Builds one donut chart with a big number in the middle."""
        df_d = pd.DataFrame({"label": labels, "value": data})
        base = alt.Chart(df_d).encode(
            theta=alt.Theta("value:Q", stack=True),
            color=alt.Color("label:N", scale=alt.Scale(domain=labels, range=colors), legend=None),
            tooltip=[alt.Tooltip("label:N", title="category"), alt.Tooltip("value:Q", title="count")],
        )
        arc = base.mark_arc(innerRadius=52, outerRadius=78, cornerRadius=3, padAngle=0.015)
        center = alt.Chart(pd.DataFrame({"t": [str(center_num)]})).mark_text(
            size=26, font="Space Grotesk", fontWeight="bold", color=TEXT_MAIN
        ).encode(text="t:N")
        sub = alt.Chart(pd.DataFrame({"t": [center_label]})).mark_text(
            size=10, dy=20, font="IBM Plex Mono", color=TEXT_MUTED
        ).encode(text="t:N")
        return (arc + center + sub).properties(width=190, height=190).configure_view(
            strokeWidth=0
        ).configure(background=BG_PANEL)


    def legend_rows(labels, values, colors):
        html = ""
        for lab, val, col in zip(labels, values, colors):
            html += f'''<div style="display:flex; justify-content:space-between; align-items:center; font-size:12px; padding:4px 0;">
                <span style="display:flex; align-items:center; gap:7px;"><span style="width:8px;height:8px;border-radius:50%;background:{col};display:inline-block;"></span>{lab}</span>
                <span style="color:{TEXT_MUTED}">{val}</span></div>'''
        return html

    st.markdown('<div class="section-label">Anomalous flows &amp; threat severity</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-hint">The same numbers from above, shown as composition — how much of the network is misbehaving, and how serious it is.</div>', unsafe_allow_html=True)

    d1, d2, d3 = st.columns(3)

    normal_hosts = active_hosts - anomalous_hosts
    sev_critical_n = len(alerts[alerts["confidence_percent"] >= 90])
    sev_medium_n = len(alerts[(alerts["confidence_percent"] >= 70) & (alerts["confidence_percent"] < 90)])
    sev_low_n = len(alerts[alerts["confidence_percent"] < 70])
    proto_counts = traffic["protocol"].value_counts()

    with d1:
        st.markdown(f'<div class="panel" style="text-align:center;"><div class="section-hint" style="margin:0 0 6px 0;">Hosts on the network</div>', unsafe_allow_html=True)
        st.altair_chart(donut([normal_hosts, anomalous_hosts], ["Normal", "Anomalous"], [SAFE, CRITICAL],
                               active_hosts, "hosts"), use_container_width=True)
        st.markdown(legend_rows(["Normal", "Anomalous"], [normal_hosts, anomalous_hosts], [SAFE, CRITICAL]) + "</div>", unsafe_allow_html=True)

    with d2:
        st.markdown(f'<div class="panel" style="text-align:center;"><div class="section-hint" style="margin:0 0 6px 0;">Alerts by severity</div>', unsafe_allow_html=True)
        st.altair_chart(donut([sev_critical_n, sev_medium_n, sev_low_n], ["Critical (\u226590%)", "Medium (70-89%)", "Low (<70%)"],
                               [CRITICAL, WARN, FLOW], len(alerts), "alerts"), use_container_width=True)
        st.markdown(legend_rows(["Critical (\u226590%)", "Medium (70-89%)", "Low (<70%)"],
                                 [sev_critical_n, sev_medium_n, sev_low_n], [CRITICAL, WARN, FLOW]) + "</div>", unsafe_allow_html=True)

    with d3:
        st.markdown(f'<div class="panel" style="text-align:center;"><div class="section-hint" style="margin:0 0 6px 0;">Protocol mix (all traffic)</div>', unsafe_allow_html=True)
        proto_colors = [FLOW, INFO, WARN][:len(proto_counts)]
        st.altair_chart(donut(proto_counts.values.tolist(), proto_counts.index.tolist(), proto_colors,
                               f"{len(traffic):,}", "packets"), use_container_width=True)
        st.markdown(legend_rows(proto_counts.index.tolist(), proto_counts.values.tolist(), proto_colors) + "</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    # =====================================================================
    # TRAFFIC & THREATS OVER TIME
    # =====================================================================
    st.markdown('<div class="section-label">Traffic &amp; threats over time</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-hint">Packet volume across the session, with each detected threat marked at the moment it fired.</div>', unsafe_allow_html=True)

    BUCKET = 10
    traffic["bucket"] = (traffic["timestamp"] // BUCKET) * BUCKET
    volume = traffic.groupby("bucket").size().reset_index(name="packets")

    area = alt.Chart(volume).mark_area(
        line={"color": FLOW, "strokeWidth": 1.6},
        color=alt.Gradient(gradient="linear",
            stops=[alt.GradientStop(color=BG_PANEL_ALT, offset=0), alt.GradientStop(color=FLOW, offset=1)],
            x1=1, x2=1, y1=1, y2=0),
        opacity=0.35, interpolate="monotone",
    ).encode(
        x=alt.X("bucket:Q", title="time (seconds)", axis=alt.Axis(grid=False)),
        y=alt.Y("packets:Q", title="packets / 10s", axis=alt.Axis(grid=True, gridColor=BORDER)),
        tooltip=[alt.Tooltip("bucket:Q", title="t (s)"), alt.Tooltip("packets:Q", title="packets")],
    )

    alerts_plot = alerts.copy()
    alerts_plot["color"] = alerts_plot["category"].map(CATEGORY_COLORS).fillna(DEFAULT_CAT_COLOR)
    rules = alt.Chart(alerts_plot).mark_rule(strokeWidth=2, strokeDash=[3, 2]).encode(
        x="timestamp:Q", color=alt.Color("color:N", scale=None, legend=None),
        tooltip=[alt.Tooltip("category:N", title="threat"), alt.Tooltip("src_ip:N", title="source"),
                 alt.Tooltip("confidence_percent:Q", title="confidence %")],
    )
    points = alt.Chart(alerts_plot).mark_point(size=90, filled=True, shape="triangle-down").encode(
        x="timestamp:Q", y=alt.value(6), color=alt.Color("color:N", scale=None, legend=None),
        tooltip=[alt.Tooltip("category:N", title="threat"), alt.Tooltip("src_ip:N", title="source"),
                 alt.Tooltip("confidence_percent:Q", title="confidence %")],
    )

    chart = (area + rules + points).properties(height=260).configure_view(strokeWidth=0).configure(
        background=BG_PANEL,
    ).configure_axis(labelColor=TEXT_MUTED, titleColor=TEXT_MUTED, labelFont="IBM Plex Mono", titleFont="IBM Plex Mono", labelFontSize=10)
    st.altair_chart(chart, use_container_width=True)

    legend_html = "".join(
        f'<span style="margin-right:16px;font-size:11px;color:{TEXT_MUTED}">'
        f'<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:{c};margin-right:5px"></span>{cat}</span>'
        for cat, c in CATEGORY_COLORS.items()
    )
    st.markdown(f'<div style="margin:-6px 0 24px 4px">{legend_html}</div>', unsafe_allow_html=True)

    # =====================================================================
    # PIPELINE
    # =====================================================================
    st.markdown('<div class="section-label">Detection pipeline</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-hint">Every layer is an AI decision (Random Forest or Isolation Forest), gated by how much evidence that attack type realistically needs before the verdict can be trusted.</div>', unsafe_allow_html=True)

    pipeline_html = '<div class="pipeline-wrap">'
    for i, layer in enumerate(LAYER_META):
        count = len(alerts[alerts["layer"] == layer["key"]])
        hot = "hot" if count > 0 else ""
        pipeline_html += f'''<div class="pipe-node {hot}"><div class="pipe-num">{layer["num"]}</div>
            <div class="pipe-name">{layer["name"]}</div><div class="pipe-window">{layer["window"]}</div>
            <div class="pipe-catches">{layer["catches"]}</div><div class="pipe-count">{count}</div></div>'''
        if i < len(LAYER_META) - 1:
            pipeline_html += '<div class="pipe-arrow">&#8594;</div>'
    pipeline_html += "</div>"
    st.markdown(pipeline_html, unsafe_allow_html=True)

    # =====================================================================
    # ENCRYPTED TRAFFIC FINGERPRINT (JA3 MATCH FEED)
    # =====================================================================
    st.markdown('<div class="section-label">Encrypted traffic fingerprint &mdash; JA3 match feed</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-hint">Even inside encrypted (HTTPS) traffic, the way a connection is set up leaves a fingerprint. We check every one seen against a feed of known-malicious tool signatures.</div>', unsafe_allow_html=True)

    ja3_alerts = alerts[alerts["ja3"].fillna("") != ""] if "ja3" in alerts.columns else alerts.iloc[0:0]
    matched_ja3 = set(ja3_alerts["ja3"]) if "ja3" in ja3_alerts.columns else set()

    ja3_html = '<div class="panel">'
    for entry in ja3_feed:
        h, threat = entry["ja3"], entry["threat"]
        is_match = h in matched_ja3
        if is_match:
            hits = ja3_alerts[ja3_alerts["ja3"] == h]
            n_hosts = hits["src_ip"].nunique()
            tag = f'<span class="pill pill-flagged">{n_hosts} host{"s" if n_hosts != 1 else ""} matched</span>'
        else:
            tag = '<span class="pill pill-normal">no match</span>'
        ja3_html += f'''<div class="ja3-row"><div class="ja3-top">
            <div><div class="ja3-threat">{threat}</div><div class="ja3-hash">JA3 {h}</div></div>{tag}</div></div>'''
    ja3_html += "</div>"
    st.markdown(ja3_html, unsafe_allow_html=True)

    st.markdown("<div style='height:22px'></div>", unsafe_allow_html=True)

    # =====================================================================
    # ALERT FEED
    # =====================================================================
    st.markdown('<div class="section-label">Alert feed</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-hint">Each alert leads with visual evidence, not just a paragraph — an icon for what kind of threat it is, a ring for how confident we are, and a small chart of the actual pattern that triggered it.</div>', unsafe_allow_html=True)

    CATEGORY_ICONS = {
        "Flood / DoS": '<svg viewBox="0 0 24 24"><rect x="3" y="13" width="4" height="8" rx="1" fill="{c}"/><rect x="10" y="8" width="4" height="13" rx="1" fill="{c}"/><rect x="17" y="3" width="4" height="18" rx="1" fill="{c}"/></svg>',
        "Port Scan / Reconnaissance": '<svg viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2"><circle cx="12" cy="12" r="2.5" fill="{c}" stroke="none"/><circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="10.5"/></svg>',
        "DNS Tunneling / C2 Beaconing": '<svg viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round"><circle cx="4.5" cy="12" r="2" fill="{c}" stroke="none"/><circle cx="19" cy="5" r="2" fill="{c}" stroke="none"/><circle cx="19" cy="19" r="2" fill="{c}" stroke="none"/><line x1="6.5" y1="12" x2="17" y2="6"/><line x1="6.5" y1="12" x2="17" y2="18"/></svg>',
        "Covert Timing Channel (hidden data exfiltration)": '<svg viewBox="0 0 24 24"><rect x="1.5" y="15" width="2.5" height="6" fill="{c}"/><rect x="6" y="7" width="2.5" height="14" fill="{c}"/><rect x="10.5" y="16" width="2.5" height="5" fill="{c}"/><rect x="15" y="4" width="2.5" height="17" fill="{c}"/><rect x="19.5" y="13" width="2.5" height="8" fill="{c}"/></svg>',
        "Encrypted C2 (malicious TLS fingerprint)": '<svg viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linejoin="round"><rect x="4.5" y="11" width="15" height="10" rx="2"/><path d="M7.5 11V7a4.5 4.5 0 0 1 9 0v4"/></svg>',
    }

    def icon_badge(category, color):
        svg = CATEGORY_ICONS.get(category, "").format(c=color)
        return f'''<div style="width:40px;height:40px;border-radius:10px;background:{color}22;
            display:flex;align-items:center;justify-content:center;flex-shrink:0;">
            <div style="width:19px;height:19px;">{svg}</div></div>'''

    def confidence_ring(pct, color):
        return f'''<div style="width:50px;height:50px;border-radius:50%;flex-shrink:0;
            background: conic-gradient({color} {pct}%, {BG_PANEL_ALT} {pct}% 100%);
            display:flex;align-items:center;justify-content:center;">
            <div style="width:38px;height:38px;border-radius:50%;background:{BG_PANEL};
                display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;
                color:{TEXT_MAIN};font-family:'Space Grotesk',sans-serif;">{pct:.0f}%</div></div>'''

    FLOOD_ALARM_THRESHOLD = 50  # packets per 5s that trips Layer 1 — mirrors detector.py's FLOOD_THRESHOLD

    def evidence_flood(src_ip, color):
        """Mini bar chart: packets per 0.5s, padded with quiet time before/after
        the burst. Bins under the alarm threshold are drawn in green ('this is
        what normal looks like'), bins over it in red ('this is the attack') —
        so the contrast is a color difference, not just a height difference."""
        g = traffic[traffic["src_ip"] == src_ip]
        if g.empty:
            return ""
        burst_start, burst_end = g["timestamp"].min(), g["timestamp"].max()
        pad = 4.0  # seconds of quiet padding on each side, for visual "before/after"
        win_start, win_end = burst_start - pad, burst_end + pad
        bin_size = 0.5
        n_bins = int((win_end - win_start) / bin_size) + 1
        counts = [0] * n_bins
        for t in g["timestamp"]:
            idx = int((t - win_start) / bin_size)
            if 0 <= idx < n_bins:
                counts[idx] += 1
        maxv = max(max(counts), 1)
        threshold_per_bin = FLOOD_ALARM_THRESHOLD / (5.0 / bin_size)  # scale the 5s alarm threshold to this bin size
        bars = "".join(
            f'<div style="width:5px;height:{max(4,int(c/maxv*32))}px;'
            f'background:{color if c>threshold_per_bin else SAFE};border-radius:1px;"></div>'
            for c in counts[:60]
        )
        return f'''<div style="display:flex;align-items:flex-end;gap:2px;height:34px;">{bars}</div>
            <div style="display:flex;gap:14px;font-size:9.5px;color:{TEXT_MUTED};margin-top:5px;">
                <span><span style="display:inline-block;width:7px;height:7px;background:{SAFE};border-radius:1px;"></span> normal rate</span>
                <span><span style="display:inline-block;width:7px;height:7px;background:{color};border-radius:1px;"></span> above the {FLOOD_ALARM_THRESHOLD} pkts/5s alarm threshold</span>
            </div>
            <div class="alert-meta" style="margin-top:4px;">quiet before &rarr; burst &rarr; quiet after, {pad:.0f}s padding shown on each side</div>'''

    def evidence_scan(src_ip, color):
        """Mini strip using the same 'knocking on doors' idea from earlier:
        green ticks = the handful of common ports (doors) normal traffic uses,
        red ticks = every port this host actually tried. Same range (1 to the
        highest port touched), so the sheer spread is the visual proof."""
        g = traffic[traffic["src_ip"] == src_ip]
        ports = sorted(g["dst_port"].unique())
        if not ports:
            return ""
        maxport = max(max(ports), 443)
        common = [p for p in [80, 443, 22, 53] if p <= maxport]
        common_ticks = "".join(f'<div style="position:absolute;left:{p/maxport*100:.1f}%;width:2px;height:100%;background:{SAFE};"></div>' for p in common)
        scan_ticks = "".join(f'<div style="position:absolute;left:{p/maxport*100:.1f}%;width:2px;height:100%;background:{color};"></div>' for p in ports)
        return f'''<div class="alert-meta" style="margin-bottom:5px;">Which ports (like doors down a hallway) this host tried knocking on:</div>
            <div style="display:flex;flex-direction:column;gap:3px;">
                <div style="position:relative;height:9px;background:{BG_PANEL_ALT};border-radius:3px;overflow:hidden;">{common_ticks}</div>
                <div style="position:relative;height:9px;background:{BG_PANEL_ALT};border-radius:3px;overflow:hidden;">{scan_ticks}</div>
            </div>
            <div style="display:flex;gap:14px;font-size:9.5px;color:{TEXT_MUTED};margin-top:5px;">
                <span><span style="display:inline-block;width:7px;height:7px;background:{SAFE};border-radius:1px;"></span> doors normal traffic uses ({len(common)})</span>
                <span><span style="display:inline-block;width:7px;height:7px;background:{color};border-radius:1px;"></span> doors this host tried ({len(ports)})</span>
            </div>
            <div class="alert-meta" style="margin-top:4px;">{len(ports)} different ports tried in seconds &mdash; normal traffic only ever knocks on 2&ndash;4</div>'''

    def evidence_dns(src_ip, color):
        """Mini strip: each tick is one DNS check-in, placed at the moment it
        happened. Evenly spaced ticks are the visual proof of 'too regular'."""
        g = traffic[(traffic["src_ip"] == src_ip) & (traffic["dns_query"] != "")].sort_values("timestamp")
        times = g["timestamp"].values
        if len(times) < 2:
            return ""
        t0, t1 = times[0], times[-1]
        span = max(t1 - t0, 0.001)
        ticks = "".join(f'<div style="position:absolute;left:{(t-t0)/span*100:.1f}%;width:2px;height:100%;background:{color};"></div>' for t in times[:40])
        return f'''<div class="alert-meta" style="margin-bottom:5px;">Every mark is one DNS check-in, placed at the moment it happened:</div>
            <div style="position:relative;height:22px;background:{BG_PANEL_ALT};border-radius:4px;overflow:hidden;">{ticks}</div>
            <div style="display:flex;justify-content:space-between;font-size:9.5px;color:{TEXT_MUTED};margin-top:3px;">
                <span>first check-in</span><span>last check-in</span></div>
            <div class="alert-meta" style="margin-top:4px;">{len(times)} check-ins, spaced almost exactly the same every time &mdash; a person browsing never does this, a program on a timer does</div>'''

    def evidence_ja3(row, color):
        matched = str(row.get("matched_threat", "")) or "known-malicious signature"
        h = str(row.get("ja3", ""))
        return f'''<div style="display:flex;gap:8px;align-items:center;font-size:11px;font-family:'IBM Plex Mono',monospace;">
            <span style="padding:3px 8px;background:{BG_PANEL_ALT};border-radius:5px;color:{TEXT_MUTED};">observed&nbsp; {h[:20]}...</span>
            <span style="color:{color};">=</span>
            <span style="padding:3px 8px;background:{color}22;border-radius:5px;color:{color};">feed match &mdash; {matched}</span>
        </div>'''

    def evidence_covert(bits, color):
        if not (isinstance(bits, str) and bits):
            return ""
        bars = "".join(
            f'<div class="decoded-bar {"one" if b == "1" else ""}" '
            f'style="width:4px; height:{10 if b=="0" else 20}px;"></div>' for b in bits[:50])
        return f'''<div class="decoded-track">{bars}</div>
            <div class="alert-meta" style="margin-top:6px;">decoded signal, first {min(50,len(bits))} gaps &mdash; short=0, long=1</div>
            <div class="decoded-bits-text">{bits}</div>'''

    MODEL_LABELS = {
        "random_forest": "Random Forest", "isolation_forest": "Isolation Forest",
        "logistic_regression": "Logistic Regression", "decision_tree": "Decision Tree",
        "kmeans": "K-Means",
    }

    def model_chips(src_ip, color):
        """The actual final verdict, called out distinctly — then the
        other 4 models' opinions shown as smaller supporting chips.
        Not all 5 are equal votes: one of them is literally the model
        whose decision became this alert."""
        try:
            batches = fetch_json(f"/api/ml/predictions/{src_ip}")
        except Exception:
            return ""
        if not batches:
            return ""
        opinions = batches[0]["opinions"]  # most recent detection event for this host
        verdict = next((o for o in opinions if o["is_final_verdict"]), None)
        supporting = [o for o in opinions if not o["is_final_verdict"]]

        verdict_html = ""
        if verdict:
            label = MODEL_LABELS.get(verdict["model"], verdict["model"])
            conf_txt = f" &middot; {verdict['confidence']*100:.0f}% confidence" if verdict["confidence"] is not None else ""
            verdict_html = f'''<div style="display:flex;align-items:center;gap:10px;
                padding:9px 14px;margin-bottom:8px;background:{color}18;
                border:1.5px solid {color};border-radius:8px;">
                <span style="font-size:9px;font-weight:700;letter-spacing:0.06em;color:{color};
                    text-transform:uppercase;">Final verdict</span>
                <span style="color:{TEXT_MUTED};font-size:11px;">{label} decided this one</span>
                <span style="margin-left:auto;color:{TEXT_MAIN};font-weight:700;font-size:12px;">
                    {verdict['predicted_label']}{conf_txt}</span>
            </div>'''

        chips = ""
        for op in supporting:
            label = MODEL_LABELS.get(op["model"], op["model"])
            conf_txt = f" &middot; {op['confidence']*100:.0f}%" if op["confidence"] is not None else ""
            chips += f'''<div style="display:inline-flex;align-items:center;gap:6px;
                padding:5px 10px;margin:3px 5px 3px 0;background:{BG_PANEL_ALT};
                border:1px solid {BORDER};border-radius:20px;font-size:10.5px;">
                <span style="color:{TEXT_MUTED};">{label}</span>
                <span style="color:{TEXT_MAIN};font-weight:600;">{op['predicted_label']}{conf_txt}</span>
            </div>'''
        return f'''{verdict_html}
            <div class="alert-meta" style="margin-bottom:6px;">Other models' opinions on the same host:</div>
            <div style="line-height:2.1;">{chips}</div>'''

    for _, row in alerts.sort_values("timestamp").iterrows():
        cat = row["category"]
        color = CATEGORY_COLORS.get(cat, DEFAULT_CAT_COLOR)

        if cat == "Flood / DoS":
            evidence = evidence_flood(row["src_ip"], color)
        elif cat == "Port Scan / Reconnaissance":
            evidence = evidence_scan(row["src_ip"], color)
        elif cat == "DNS Tunneling / C2 Beaconing":
            evidence = evidence_dns(row["src_ip"], color)
        elif cat == "Covert Timing Channel (hidden data exfiltration)":
            evidence = evidence_covert(row.get("decoded_bits", ""), color)
        elif cat == "Encrypted C2 (malicious TLS fingerprint)":
            evidence = evidence_ja3(row, color)
        else:
            evidence = ""

        st.markdown(f"""
        <details class="alert-card {severity(row['confidence_percent'])}">
            <summary class="alert-summary">
                {icon_badge(cat, color)}
                <div class="alert-summary-text">
                    <div class="alert-category">{cat}</div>
                    <div class="alert-layer">{row['layer']} &nbsp;&middot;&nbsp; <span class="latency-tag">detected in {row['detection_latency_sec']}s</span></div>
                </div>
                {confidence_ring(row['confidence_percent'], color)}
                <span class="alert-chevron">&#9656;</span>
            </summary>
            <div class="alert-details">
                <div class="alert-explain">{row['explanation']}</div>
                <div class="evidence-wrap">{evidence}</div>
                <div class="evidence-wrap">{model_chips(row['src_ip'], color)}</div>
                <div class="alert-meta">source <code>{row['src_ip']}</code> &nbsp;&middot;&nbsp; t = {row['timestamp']}s</div>
            </div>
        </details>""", unsafe_allow_html=True)

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    # =====================================================================
    # CATEGORY BREAKDOWN + ACTIVE HOSTS + LATENCY BY LAYER
    # =====================================================================
    c1, c2, c3, c4 = st.columns([1, 1, 1, 1])

    with c1:
        st.markdown('<div class="section-label">Threats by category</div>', unsafe_allow_html=True)
        cat_counts = alerts["category"].value_counts()
        total = cat_counts.sum()
        bars_html = '<div class="panel">'
        for cat, count in cat_counts.items():
            pct = count / total * 100
            color = CATEGORY_COLORS.get(cat, DEFAULT_CAT_COLOR)
            short_cat = cat.split(" (")[0]
            bars_html += f'''<div class="cat-row">
                <div class="cat-row-top"><span class="cat-name"><span class="cat-dot" style="background:{color}"></span>{short_cat}</span>
                <span class="cat-count">{count}</span></div>
                <div class="cat-track"><div class="cat-fill" style="width:{pct}%;background:{color}"></div></div></div>'''
        bars_html += "</div>"
        st.markdown(bars_html, unsafe_allow_html=True)

    with c2:
        st.markdown('<div class="section-label">Active hosts</div>', unsafe_allow_html=True)
        top_hosts = traffic["src_ip"].value_counts().head(6)
        hosts_html = '<div class="panel">'
        for ip, count in top_hosts.items():
            pill = status_pill(ip) if ip in flagged_ips else '<span class="pill pill-normal">normal</span>'
            hosts_html += f'''<div class="host-row"><span>{ip}</span>
                <span class="host-count">{count} pkts</span>{pill}</div>'''
        hosts_html += "</div>"
        st.markdown(hosts_html, unsafe_allow_html=True)

    with c3:
        st.markdown('<div class="section-label">Top targeted ports</div>', unsafe_allow_html=True)
        port_counts = traffic["dst_port"].value_counts().head(6)
        max_port_count = port_counts.max()
        COMMON_PORT_NAMES = {80: "http", 443: "https", 53: "dns", 22: "ssh"}
        ports_html = '<div class="panel">'
        for port, count in port_counts.items():
            pct = count / max_port_count * 100
            label = f"{port} ({COMMON_PORT_NAMES[port]})" if port in COMMON_PORT_NAMES else str(port)
            color = SAFE if port in COMMON_PORT_NAMES else WARN  # uncommon ports = scan-ish, worth a glance
            ports_html += f'''<div class="cat-row">
                <div class="cat-row-top"><span class="cat-name">{label}</span><span class="cat-count">{count}</span></div>
                <div class="cat-track"><div class="cat-fill" style="width:{pct}%;background:{color}"></div></div></div>'''
        ports_html += "</div>"
        st.markdown(ports_html, unsafe_allow_html=True)

    with c4:
        st.markdown('<div class="section-label">Detection latency by layer</div>', unsafe_allow_html=True)
        lat_by_layer = alerts.groupby("layer")["detection_latency_sec"].mean().reindex(
            [l["key"] for l in LAYER_META]
        ).dropna()
        lat_html = '<div class="panel">'
        max_lat = max(lat_by_layer.max(), 1)
        for layer_key, lat in lat_by_layer.items():
            short_name = next(l["name"] for l in LAYER_META if l["key"] == layer_key)
            pct = min(100, lat / max_lat * 100)
            lat_html += f'''<div class="cat-row">
                <div class="cat-row-top"><span class="cat-name">{short_name}</span><span class="cat-count">{lat:.1f}s</span></div>
                <div class="cat-track"><div class="cat-fill" style="width:{pct}%;background:{FLOW}"></div></div></div>'''
        lat_html += "</div>"
        st.markdown(lat_html, unsafe_allow_html=True)


# =====================================================================
# PAGE: LIVE TRAFFIC FEED (unchanged content, just moved into a function
# so it opens as its own page instead of sitting inline on Overview)
# =====================================================================
def render_live_feed_page():
    if st.button("←  Back to overview", key="back_to_overview"):
        st.switch_page(page_overview)
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

    # =====================================================================
    # LIVE TRAFFIC FEED
    # =====================================================================
    st.markdown('<div class="section-label"><span class="live-dot"></span>Live traffic feed</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-hint">A scrolling view of one-way flows as they were captured — source, destination, protocol, size, and live status. Flagged rows blink red — click one to see why it was flagged. Hover a country to see city, ISP, and ASN. <span class="geo-sim-tag">sim</span> marks simulated geolocation (the demo traffic uses non-routable documentation IPs — see code comments for wiring in a real lookup).</div>', unsafe_allow_html=True)

    def render_feed_table(rows_df):
        header = """<div class="flow-header">
            <span>time (s)</span><span>source</span><span>country</span><span>destination</span>
            <span>port</span><span>proto</span><span>size</span><span>dns query</span><span>status</span>
        </div>"""
        body = ""
        for i, r in enumerate(rows_df.itertuples()):
            dns = r.dns_query if r.dns_query else "&mdash;"
            cells = f"""<span>{r.timestamp:.2f}</span><span>{r.src_ip}</span><span>{geo_chip(r.src_ip)}</span>
                <span>{r.dst_ip}</span><span>{r.dst_port}</span><span>{r.protocol}</span>
                <span>{r.packet_size}</span><span>{dns}</span>"""
            if r.src_ip in flagged_ips:
                # flagged row: blinking red notification dot + click to expand details
                match = alerts[alerts["src_ip"] == r.src_ip].iloc[0]
                row_id = f"flow-{i}-{abs(hash(r.src_ip)) % 100000}"
                body += f"""<input type="checkbox" id="{row_id}" class="flow-toggle">
                <label for="{row_id}" class="flow-row flagged clickable">
                    {cells}<span><span class="blink-dot"></span>{status_pill(r.src_ip)}</span>
                </label>
                <div class="flow-detail">
                    <b style="color:{CATEGORY_COLORS.get(match['category'], DEFAULT_CAT_COLOR)}">{match['category']}</b>
                    &nbsp;&middot;&nbsp; {match['layer']} &nbsp;&middot;&nbsp; {match['confidence_percent']}% confidence
                    <div style="margin-top:6px;">{match['explanation']}</div>
                </div>"""
            else:
                body += f"""<div class="flow-row">{cells}<span>{status_pill(r.src_ip)}</span></div>"""
        if not body:
            body = '<div style="padding:24px; text-align:center; color:var(--text-muted); font-size:12.5px;">No flows match the current filters.</div>'
        return f"""<div class="panel" style="padding:8px 14px 14px 14px; max-height:420px; overflow-y:auto; overflow-x:visible;">
        {header}{body}</div>"""

    def stats_bar_html(window_df, true_total):
        flows = len(window_df)
        flagged_n = int(window_df["src_ip"].isin(flagged_ips).sum()) if flows else 0
        total_bytes = int(window_df["packet_size"].sum()) if flows else 0
        size_str = f"{total_bytes/1024:.1f} KB"
        return f"""<div class="livebar">
            <span><b>{flows}</b> flows shown</span>
            <span><b>{flagged_n}</b> flagged</span>
            <span><b>{size_str}</b> transferred</span>
            <span class="livebar-muted">{true_total} total flows match current filters</span>
        </div>"""

    # ---------------- FILTERS ----------------
    fc1, fc2, fc3 = st.columns([1, 1.1, 1.3])
    with fc1:
        only_flagged = st.checkbox("Show only flagged", value=False)
    with fc2:
        cat_options = ["All"] + sorted(alerts["category"].unique().tolist())
        category_filter = st.selectbox("Category", cat_options)
    with fc3:
        ip_search = st.text_input("Search source IP", placeholder="e.g. 203.0.113")

    filtered = traffic
    if only_flagged:
        filtered = filtered[filtered["src_ip"].isin(flagged_ips)]
    if category_filter != "All":
        cat_ips = {ip for ip, c in ip_to_category.items() if c == category_filter}
        filtered = filtered[filtered["src_ip"].isin(cat_ips)]
    if ip_search.strip():
        filtered = filtered[filtered["src_ip"].str.contains(ip_search.strip(), regex=False, na=False)]

    # reset playback whenever the filters actually change, so we never show
    # a stale window built from the previous filter selection
    filter_sig = (only_flagged, category_filter, ip_search.strip())
    if "live_feed_filter_sig" not in st.session_state:
        st.session_state.live_feed_filter_sig = None
    if "live_feed_playing" not in st.session_state:
        st.session_state.live_feed_playing = False
    if "live_feed_index" not in st.session_state:
        st.session_state.live_feed_index = 0
    if filter_sig != st.session_state.live_feed_filter_sig:
        st.session_state.live_feed_filter_sig = filter_sig
        st.session_state.live_feed_index = 0
        st.session_state.live_feed_playing = False

    filtered_flagged = [ip for ip in flagged_ips if ip in set(filtered["src_ip"])]
    filtered_normal_pool = filtered[~filtered["src_ip"].isin(flagged_ips)]
    attacker_chunks = []
    for ip in filtered_flagged:
        g = filtered[filtered["src_ip"] == ip]
        attacker_chunks.append(g.sample(min(12, len(g)), random_state=7))
    attacker_sample = pd.concat(attacker_chunks) if attacker_chunks else filtered.iloc[0:0]
    normal_sample = (
        filtered_normal_pool.sample(min(55, len(filtered_normal_pool)), random_state=7)
        if len(filtered_normal_pool) else filtered_normal_pool
    )
    display_pool = pd.concat([attacker_sample, normal_sample]).sort_values("timestamp").reset_index(drop=True)

    # ---------------- PLAY / PAUSE ----------------
    pc1, pc2, _ = st.columns([1, 1, 3])
    with pc1:
        if st.button("▶  Play", disabled=len(display_pool) == 0, use_container_width=True):
            if st.session_state.live_feed_index >= len(display_pool):
                st.session_state.live_feed_index = 0
            st.session_state.live_feed_playing = True
    with pc2:
        if st.button("⏸  Pause", use_container_width=True):
            st.session_state.live_feed_playing = False

    st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

    if len(display_pool) == 0:
        st.markdown(stats_bar_html(display_pool, len(filtered)), unsafe_allow_html=True)
        st.markdown(render_feed_table(display_pool), unsafe_allow_html=True)
    else:
        @st.fragment(run_every=0.15 if st.session_state.live_feed_playing else None)
        def live_feed_fragment():
            if st.session_state.live_feed_playing:
                st.session_state.live_feed_index = min(len(display_pool), st.session_state.live_feed_index + 2)
                if st.session_state.live_feed_index >= len(display_pool):
                    st.session_state.live_feed_playing = False
            idx = st.session_state.live_feed_index
            window = display_pool.tail(14) if idx == 0 else display_pool.iloc[max(0, idx - 14):idx]
            st.markdown(stats_bar_html(window, len(filtered)), unsafe_allow_html=True)
            st.markdown(render_feed_table(window), unsafe_allow_html=True)
            if idx >= len(display_pool) and idx > 0:
                st.caption("Replay finished — showing the last 14 flows observed.")

        live_feed_fragment()


# =====================================================================
# NAVIGATION — two real pages (each with its own URL), no sidebar shown
# (position="hidden") since the only requested navigation is the button
# above, not an automatic nav menu.
# =====================================================================
page_overview = st.Page(render_overview_page, title="Overview", url_path="overview", default=True)
page_live_feed = st.Page(render_live_feed_page, title="Live Feed", url_path="live-feed")
nav = st.navigation([page_overview, page_live_feed], position="hidden")
nav.run()
