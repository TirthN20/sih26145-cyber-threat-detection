# Attack simulation scripts

Five scripts, one per detection layer — each sends real packets to your
running backend through `/api/ingest`, live, and prints exactly when
and why an alert fires. Good for demos, and good for proving the
system reacts to genuinely new attackers, not just the pre-loaded
demo data.

## Before running any of these

Your backend must already be running in a separate terminal:
```
uvicorn main_mysql:app --reload
```

## The 5 scripts

| Script | Simulates | Fires after |
|---|---|---|
| `simulate_flood.py` | Flood / DoS | ~51 packets in 3 seconds |
| `simulate_port_scan.py` | Port Scan | ~16 different ports in 12 seconds |
| `simulate_dns_tunnel.py` | DNS Tunneling / C2 Beaconing | 5 robotic-regular DNS check-ins |
| `simulate_covert_channel.py` | Covert Timing Channel | 30 packets with encoded bit-timing |
| `simulate_ja3_match.py` | Encrypted C2 (JA3 match) | 1 connection (instant — signature match) |

Run any of them with:
```
python simulate_flood.py
```
(swap in whichever filename you want)

## Important: each script uses one fixed IP

If you run the **same script twice**, the second run reuses the same
IP and timestamp range — this can produce a confusing, inflated
"detection latency" number (we ran into exactly this earlier). If you
want to re-test one, **open the script and change the
`NEW_ATTACKER_IP` value** to something you haven't used before (just
change the last number, e.g. `.60` to `.90`) before running it again.

## Tested

Every script here was run against a live backend before being handed
over — all 5 fired the correct alert, with sensible confidence and a
matching explanation, exactly as shown in each script's own output.
