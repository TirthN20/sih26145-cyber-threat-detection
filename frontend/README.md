# SIH 26145 — Unidirectional Cyber Threat Detector
### A complete, working prototype — step by step, assuming zero coding experience

This project has 4 files that work together:

1. `generate_traffic.py` → creates a pretend (synthetic) network traffic log,
   including 10 hidden attackers across 5 threat categories, saved as `traffic_log.csv`
2. `ja3_threat_feed.json` → a small list of known-malicious encrypted-traffic
   fingerprints (like a real threat intelligence feed) - used by both the
   generator and the detector, don't delete this file
3. `detector.py` → analyzes traffic through 5 detection layers and finds
   the hidden attacks, saved as `alerts.csv`
4. `dashboard.py` → shows the results as a full-screen visual dashboard for your demo

---

## PART 1 — One-time setup (do this once)

### Step 1: Install Python
1. Go to https://www.python.org/downloads/
2. Download and install the latest version.
3. **Important (Windows only):** on the first install screen, tick the box
   that says "Add Python to PATH" before clicking Install.

### Step 2: Check it worked
Open a terminal:
- **Windows:** press the Start button, type `cmd`, press Enter.
- **Mac:** open the "Terminal" app (search for it with Spotlight, Cmd+Space).

Type this and press Enter:
```
python3 --version
```
(On Windows, if that doesn't work, try `python --version` instead.)
You should see something like `Python 3.12.3`. If you see an error, Python
wasn't installed correctly — reinstall and make sure "Add to PATH" was ticked.

### Step 3: Put the project files in one folder
Create a folder anywhere on your computer, e.g. `Desktop/sih26145`, and put
all 3 `.py` files AND `ja3_threat_feed.json` into that same folder (all 4
files side by side, no subfolders).

### Step 4: Open a terminal INSIDE that folder
- **Windows:** open the folder in File Explorer, click the address bar at
  the top, type `cmd`, press Enter — a terminal opens already inside the folder.
- **Mac:** open Terminal, type `cd ` (with a space after it), then drag the
  folder into the terminal window, then press Enter.

### Step 5: Install the required packages (one-time)
Copy-paste this exact line and press Enter:
```
pip install pandas numpy streamlit altair
```
Wait for it to finish (you'll see a lot of text scroll — that's normal).
If `pip` doesn't work, try `pip3 install pandas numpy streamlit` instead.

---

## PART 2 — Running the project (do this every time you demo)

Make sure your terminal is open inside the project folder (Step 4 above),
then run these three commands **one at a time**, in this exact order:

### Command 1 — generate the fake traffic
```
python3 generate_traffic.py
```
You should see text confirming packets were generated, and a new file
`traffic_log.csv` will appear in the folder.

### Command 2 — run the detector
```
python3 detector.py
```
You should see 10 alerts printed to the screen across 5 threat categories
(Encrypted C2 fingerprint match, Flood/DoS, Port Scan, DNS Tunneling, Covert
Timing Channel), each with a plain-English explanation and how fast it was
caught. A new file `alerts.csv` will appear.

### Command 3 — open the visual dashboard
```
streamlit run dashboard.py
```
A browser tab opens automatically at `http://localhost:8501` with the full
dashboard: live stats, a traffic timeline with threats marked, the 5-layer
detection pipeline, the JA3 encrypted-fingerprint match feed, explained
alerts (including a decoded visual for the covert channel signal), and a
live traffic feed you can press "▶ Play live replay" on to animate. Leave
this terminal window open while demoing - closing it shuts down the
dashboard. Press `Ctrl+C` in the terminal when you're done.

---

## PART 3 — What to actually say during your demo

Walk through it in this order, it tells a story:

1. **Show the dashboard is live and clean** — "This is analyzing traffic from
   a network where we can only see one direction of communication, simulating
   a real gateway or data-diode monitoring point."
2. **Point at the 5 categories and the timeline chart** — "Instead of one flat
   detector, we run five checks at different speeds, because different attacks
   take different amounts of time to reveal themselves. You can see exactly
   when each one fired on the timeline."
3. **Click into the Encrypted C2 (JA3 fingerprint) alert** — "This one is
   caught instantly, before we even see what the attacker does — just from
   the fingerprint of how their encrypted connection was set up, matched
   against a threat feed. Nothing else about this traffic looks suspicious."
4. **Point at Flood/DoS and Port Scan** — "These are caught in seconds by
   our fast layers."
5. **Point at DNS Tunneling** — "This hides in DNS lookups — it takes longer
   to catch because you need to see the pattern over time. You can see that
   reflected in the detection latency panel too."
6. **Save the Covert Timing Channel alert for last, and explain it slowly:**
   "This is the one nobody expects. The attacker isn't sending anything that
   looks malicious at all — normal size, normal port. They're hiding a
   secret message in the *timing gaps* between packets, like Morse code.
   Our system doesn't look at what's inside the packets — it looks at the
   *statistical shape* of the timing itself. And here — " *(point at the
   decoded signal strip under the alert)* " — you can literally see the
   short and long gaps we decoded into bits. This is the one attack
   specifically designed to defeat a one-way, unidirectional network, and
   it's the part of our system most other teams won't have thought about."
7. **Press "▶ Play live replay"** on the live traffic feed at the end —
   "This is what it looks like watching traffic arrive in real time, with
   every flow's status shown live."

---

## PART 4 — If something breaks

- **"pip: command not found"** → try `pip3` instead of `pip`.
- **"python3: command not found"** → try `python` instead of `python3`.
- **Dashboard shows an error about missing files** → you skipped Command 1 or
  2. Run them again in order.
- **Streamlit dashboard doesn't open automatically** → manually open your
  browser and go to `http://localhost:8501`

---

## PART 5 — Using a real public dataset instead of synthetic data (optional, for later)

Once this synthetic demo is working, you can strengthen your submission by
also showing it works on a **real, publicly available dataset**:

- **CIDDS-001** — a real, publicly downloadable, labeled dataset that is
  natively unidirectional (this matches our problem statement exactly,
  unlike most other IDS datasets which are two-directional).
  Search "CIDDS-001 Coburg intrusion detection dataset download" to find it.

You would adapt `detector.py`'s column names to match CIDDS-001's columns
(source IP, destination IP, port, bytes, timestamp), but the same 4-layer
logic applies. Mention in your pitch that your synthetic data was used to
build and validate the concept quickly, and CIDDS-001 real traffic to
validate it further — this shows judges rigor.

---

## PART 6 — The backend (a real API + database, not just scripts)

Everything above (`generate_traffic.py`, `detector.py`, `dashboard.py`)
works completely on its own — that's your safe, zero-setup demo path,
and nothing here changes it. The `backend/` folder adds a **second,
optional** layer: a real web service with a database behind it, for
when a judge asks "is this just a script, or could this actually be
deployed?"

**What it is:** a FastAPI server backed by a real SQLite database
(`backend/data.db`), exposing the exact same detection results as REST
endpoints (JSON over HTTP) instead of CSV files, plus two things the
scripts can't do:
- **`POST /api/ingest`** — send it ONE new packet as JSON, and it
  re-runs detection against that host's history immediately. Genuine
  real-time detection, not a static file.
- **`WS /ws/live`** — a real WebSocket that pushes stored traffic to
  any connected client in time order, paced out to feel live.

### Setting it up (one-time)

1. Open a **new** terminal window (leave any dashboard terminal running).
2. Navigate into the backend folder:
   ```
   cd backend
   ```
3. Install its packages:
   ```
   pip install -r requirements.txt
   ```

### Running it (every time you demo)

From inside the `backend` folder:

```
python3 seed.py
```
This loads `../traffic_log.csv` into the database and runs detection —
you'll see "Seeded 3763 packets and 10 alerts" (numbers may vary if
you regenerated traffic). Only needs re-running if you regenerate
`traffic_log.csv`.

```
uvicorn main:app --reload
```
Then open **http://127.0.0.1:8000/docs** in a browser. This is
FastAPI's free, auto-generated interactive documentation — every
endpoint is listed, and you can click "Try it out" on any of them and
run it right there, no coding, no Postman needed. This page alone is
a strong thing to show judges directly.

### What to click on to demo it

- **`GET /api/stats`** → Try it out → Execute. Same numbers as your
  dashboard's stat row, served as JSON.
- **`GET /api/alerts`** → Execute. All 10 alerts as structured JSON —
  point out that any other system (a SIEM, a mobile app, a second
  dashboard) could consume this directly.
- **`POST /api/ingest`** → Try it out, edit the example JSON body to a
  new IP, click Execute a few times with a slightly later timestamp
  each time — show it returning `"new_alerts": []` normally, then
  actually catching something once enough evidence has built up. This
  is the moment that proves it's not just replaying a file.

### A quick honest note on the WebSocket + database

- The WebSocket (`/ws/live`) is best tried from a browser's developer
  console (F12 → Console tab) while the server is running:
  ```js
  const ws = new WebSocket("ws://127.0.0.1:8000/ws/live?speed=60");
  ws.onmessage = (e) => console.log(JSON.parse(e.data));
  ```
- `backend/data.db` is a real, inspectable SQLite file — if you have
  the `sqlite3` command installed, `sqlite3 backend/data.db` then
  `SELECT * FROM alerts;` works, which is a nice "yes, there's a real
  database, not just a pandas DataFrame" moment if asked.
- `DELETE /api/reset` wipes traffic + alerts (keeps the JA3 feed) —
  useful if you want to demo `/api/ingest` building up evidence from a
  completely clean slate. Run `python3 seed.py` again afterward to
  restore the full historical demo data.

---

## PART 7 — MySQL backend + real ML models (the production upgrade)

Everything above still works exactly as before — nothing was removed.
This section adds a **second, more advanced backend** for once you've
outgrown the SQLite demo version: a real MySQL database, plus 6
trained machine learning models running alongside the rule-based
detection layers.

### Why MySQL, and why alongside SQLite (not instead of)

SQLite was the right choice for the zero-setup demo — no server to
install, just a file. MySQL is the right choice once you're past that
stage: proper concurrent access, a real server process, the kind of
setup a judge asking "is this production-ready?" expects to see. Both
backends read the exact same `detection.py` logic, so they never
disagree with each other.

### One-time setup

**1. Install MySQL or MariaDB** (MariaDB is fully MySQL-compatible —
   same SQL, same Python drivers, same everything):
   - **Windows/Mac:** download MySQL Community Server from
     https://dev.mysql.com/downloads/ and run the installer.
   - **Linux:** `sudo apt install mariadb-server`

**2. Start the server and create the database:**
   ```
   sudo service mariadb start      (or: sudo service mysql start)
   mysql -u root
   ```
   Then, inside the `mysql>` prompt:
   ```sql
   CREATE DATABASE sih26145 CHARACTER SET utf8mb4;
   CREATE USER 'sih_app'@'localhost' IDENTIFIED BY 'sih_app_pw_2026';
   GRANT ALL PRIVILEGES ON sih26145.* TO 'sih_app'@'localhost';
   FLUSH PRIVILEGES;
   EXIT;
   ```
   (Want a different password? Set it here, then set the matching
   `DB_PASSWORD` environment variable before running anything below —
   see `backend/config.py`.)

**3. Install the extra Python packages** (from inside `backend/`):
   ```
   pip install -r requirements.txt
   ```

### Running it — every time

From inside the `backend` folder, in order:

```
python3 ml_training_data.py
```
Generates a **separate, larger, more diverse** synthetic dataset
(235 hosts) specifically for training the ML models — not the same
small dataset the dashboard displays. Training on the tiny demo
dataset would just memorize those 10 attackers instead of learning a
general pattern, which is a mistake worth avoiding on purpose.

```
python3 train_models.py
```
Trains all 6 models and prints an honest accuracy report — a real
held-out test-set number for each, not a claim. Takes a few seconds.
Saves everything to `backend/models/*.joblib`.

```
python3 seed_mysql.py
```
Loads `traffic_log.csv` into MySQL and runs both the rule-based
detection AND the trained ML models over every host, storing both.

```
uvicorn main_mysql:app --reload
```
Then open **http://127.0.0.1:8000/docs** — same interactive API
documentation as before, now with an `ml` section.

### The 6 models, and what each one actually does

| Model | Job | What we saw when we tested it |
|---|---|---|
| **Logistic Regression** | Flood/DoS probability from packet rate | 100% test accuracy |
| **Decision Tree** | Normal vs Flood vs Scan, as one inspectable flowchart | 100% test accuracy, depth 2 |
| **Random Forest** | Main multi-class classifier, all 6 categories at once | 100% test accuracy; correctly classified all 10 real demo attackers with 0.79–1.0 confidence, zero false positives on normal hosts |
| **Naive Bayes** | Real-looking vs gibberish (DGA-style) domain names | ~98.6% test accuracy on a 10,000-domain synthetic corpus |
| **Isolation Forest** | Unsupervised anomaly detector, trained ONLY on normal traffic | Correctly flagged all 10 attackers as anomalous; 2 negligible borderline false positives (anomaly scores 0.002–0.008, essentially noise) |
| **K-Means** | Groups hosts by behavior, k=6 | Silhouette score 0.68; 4 of 6 clusters were pure single-category, one cluster mixed Covert Channel with JA3-matched hosts (see note below) |

**An honest finding worth knowing for Q&A:** K-Means merged the
covert-timing-channel hosts and the JA3-fingerprint-matched hosts into
one cluster. This isn't a bug — the clustering features are general
behavior stats (packet count, rate, session length), which genuinely
don't include the JA3 hash or timing-gap signals that specifically
tell those two categories apart. It's an expected, explainable
limitation, and a good example of *why* the project uses 5 different
detection layers instead of relying on one clustering pass to catch
everything.

**Also worth knowing:** these accuracy numbers are measured on a
synthetic dataset engineered to have clearly separable classes — real
network traffic would show more overlap and lower (but still
meaningful) accuracy. Say this proactively if asked; claiming
99–100% accuracy as if it were real-world performance is the kind of
overclaim a sharp judge will immediately push on.

### Try the ML endpoints directly

- **`GET /api/ml/models`** → the full training report as JSON — every
  accuracy number above, straight from the source.
- **`GET /api/ml/predict/203.0.113.78`** → runs all 5 predictive
  models live against that host's actual traffic (try it with any IP
  from the traffic table). Try a normal host too, e.g. `10.0.0.8`.
- **`POST /api/ml/predict-domain`** with body `{"domain": "google.com"}`
  vs `{"domain": "xk9fq2zvbn4mws.com"}` — watch Naive Bayes tell them
  apart from the domain string alone.

### A bug worth mentioning if asked "how do you know this works"

While building this, the very first version of the ML training data
generated "normal" traffic differently from how `generate_traffic.py`
actually does it (denser, with DNS queries that real normal traffic
in this project never has). The trained model then flagged almost
every ordinary host as suspicious when tested against the real demo
data — a classic train/serve mismatch. Fixing the training generator
to exactly mirror the real traffic pattern took the false-positive
rate from roughly 30 wrongly-flagged hosts down to 2 negligible ones.
This is a genuinely good story for a judge who asks about testing
rigor — it shows the numbers were actually checked against real
behavior, not just trusted because a test-set score looked good.
