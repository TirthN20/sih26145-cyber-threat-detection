"""
Same simulated geolocation as dashboard.py — see the long comment there
for why this is simulated rather than a real API call (the demo traffic
uses IANA-reserved documentation IP ranges, which no real geolocation
service can resolve). Kept as its own module so both the Streamlit
dashboard and this backend can share one definition instead of drifting
out of sync with two different copies.
"""

import hashlib

SIMULATED_GEO_POOL = [
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


def geolocate(ip: str) -> dict:
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
        return {"ip": ip, "country": "Internal", "city": "Private network",
                "isp": None, "asn": None, "simulated": False}
    idx = int(hashlib.md5(ip.encode()).hexdigest(), 16) % len(SIMULATED_GEO_POOL)
    country, city, isp, asn = SIMULATED_GEO_POOL[idx]
    return {"ip": ip, "country": country, "city": city, "isp": isp, "asn": asn, "simulated": True}
