"""
ML MODELS
====================================================
Six simple, explainable models — deliberately NOT deep learning, for
the same reason argued throughout this project: this is security
tooling, and every decision needs to be justifiable to a human
analyst. Each model has ONE specific job, matched to what it's
naturally good at (this mapping is the actual design decision, not
just "throw 6 models at everything"):

  Logistic Regression  -> Flood/DoS probability from rate features
                           (fast, linear, gives a clean probability)
  Decision Tree         -> Flood vs Scan vs Normal, as one inspectable
                           flowchart (fully traceable by hand)
  Random Forest          -> the main multi-class classifier, combining
                           ALL features at once (packet rate + ports +
                           timing + entropy together, votes across
                           many trees)
  Naive Bayes            -> real-looking vs gibberish domain names,
                           from character n-grams (classic text
                           classification, exactly DNS tunneling)
  Isolation Forest       -> unsupervised anomaly detector, trained
                           ONLY on normal traffic, flags anything that
                           doesn't fit — needs no attack examples,
                           so it can catch attack types it never saw
  K-Means                -> unsupervised clustering of host behavior,
                           groups similar hosts, flags small/outlier
                           clusters

All 6 train on ml_training_traffic.csv / ml_training_labels.csv
(see ml_training_data.py) and save to models/*.joblib. Swap in real
labeled data by producing the same CSV shape and re-running
train_models.py — nothing else changes.
"""

import json
import os
import numpy as np
import pandas as pd
import joblib

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.naive_bayes import MultinomialNB
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, silhouette_score

import ml_features as mf

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODEL_DIR, exist_ok=True)

RF_FEATURES = mf.FEATURE_NAMES
DT_FEATURES = ["max_rate_5s", "max_distinct_ports_30s"]
LR_FEATURES = ["max_rate_5s", "avg_packet_size"]
IF_FEATURES = mf.FEATURE_NAMES
KM_FEATURES = ["packet_count", "max_rate_5s", "max_distinct_ports_30s", "dns_count",
               "session_duration", "avg_packet_size"]


def _path(name):
    return os.path.join(MODEL_DIR, name)


def _load_training_table(bad_ja3_hashes):
    traffic = pd.read_csv("ml_training_traffic.csv")
    traffic["dns_query"] = traffic["dns_query"].fillna("")
    traffic["ja3"] = traffic["ja3"].fillna("")
    labels = pd.read_csv("ml_training_labels.csv")
    table = mf.build_feature_table(traffic, labels["src_ip"].tolist(), bad_ja3_hashes)
    table["label"] = labels.set_index("src_ip")["category"].reindex(table.index)
    return table, traffic, labels


# =====================================================================
# 1. LOGISTIC REGRESSION — Flood/DoS probability
# =====================================================================
def train_logistic_regression(table, report):
    y = (table["label"] == "Flood / DoS").astype(int)
    X = table[LR_FEATURES].values
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=7, stratify=y)
    scaler = StandardScaler().fit(X_train)
    model = LogisticRegression(max_iter=1000).fit(scaler.transform(X_train), y_train)
    acc = accuracy_score(y_test, model.predict(scaler.transform(X_test)))
    report["logistic_regression"] = {"accuracy": round(acc, 4), "features": LR_FEATURES, "test_size": len(y_test)}
    joblib.dump({"model": model, "scaler": scaler, "features": LR_FEATURES}, _path("logistic_regression.joblib"))
    return acc


# =====================================================================
# 2. DECISION TREE — Normal / Flood / Scan flowchart
# =====================================================================
def train_decision_tree(table, report):
    sub = table[table["label"].isin(["Normal", "Flood / DoS", "Port Scan / Reconnaissance"])]
    y = sub["label"].to_numpy(dtype=object)
    X = sub[DT_FEATURES].values
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=7, stratify=y)
    model = DecisionTreeClassifier(max_depth=4, random_state=7).fit(X_train, y_train)
    acc = accuracy_score(y_test, model.predict(X_test))
    report["decision_tree"] = {"accuracy": round(acc, 4), "features": DT_FEATURES, "test_size": len(y_test),
                                "tree_depth": model.get_depth()}
    joblib.dump({"model": model, "features": DT_FEATURES}, _path("decision_tree.joblib"))
    return acc


# =====================================================================
# 3. RANDOM FOREST — main multi-class classifier, all features
# =====================================================================
def train_random_forest(table, report):
    y = table["label"].to_numpy(dtype=object)
    X = table[RF_FEATURES].fillna(0).values
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=7, stratify=y)
    model = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=7).fit(X_train, y_train)
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    importances = dict(zip(RF_FEATURES, model.feature_importances_.round(4).tolist()))
    report["random_forest"] = {
        "accuracy": round(acc, 4), "features": RF_FEATURES, "test_size": len(y_test),
        "feature_importances": importances,
        "classification_report": classification_report(y_test, preds, output_dict=True, zero_division=0),
    }
    joblib.dump({"model": model, "features": RF_FEATURES}, _path("random_forest.joblib"))
    return acc


# =====================================================================
# 4. NAIVE BAYES — real-looking vs gibberish domain names
# =====================================================================
def train_naive_bayes(traffic, report):
    # trained on a dedicated labeled domain corpus (see
    # ml_training_data.generate_domain_training_set) rather than
    # incidentally extracted from host traffic — the real demo dataset's
    # normal hosts generate no DNS traffic at all, so there'd be no
    # "real-looking" examples to contrast against if we tried to pull
    # this from the same traffic simulation.
    domains_df = pd.read_csv("ml_domain_training.csv")
    domains = domains_df["domain"].tolist()
    y = domains_df["is_gibberish"].to_numpy(dtype=int)

    X_train_d, X_test_d, y_train, y_test = train_test_split(domains, y, test_size=0.25, random_state=7, stratify=y)
    vectorizer = CountVectorizer(analyzer="char", ngram_range=(2, 3), max_features=900)
    X_train = vectorizer.fit_transform(X_train_d)
    X_test = vectorizer.transform(X_test_d)
    model = MultinomialNB().fit(X_train, y_train)
    acc = accuracy_score(y_test, model.predict(X_test))
    report["naive_bayes"] = {"accuracy": round(acc, 4), "features": "char 2-3grams of domain string",
                              "test_size": len(y_test), "training_domains": len(domains)}
    joblib.dump({"model": model, "vectorizer": vectorizer}, _path("naive_bayes.joblib"))
    return acc


# =====================================================================
# 5. ISOLATION FOREST — unsupervised anomaly detector
# =====================================================================
def train_isolation_forest(table, report):
    normal = table[table["label"] == "Normal"]
    X_normal = normal[IF_FEATURES].fillna(0).values
    scaler = StandardScaler().fit(X_normal)
    model = IsolationForest(n_estimators=200, contamination=0.05, random_state=7)
    model.fit(scaler.transform(X_normal))

    # evaluate: does it correctly call attacks "anomalous" and normals "not"?
    X_all = table[IF_FEATURES].fillna(0).values
    preds = model.predict(scaler.transform(X_all))  # -1 = anomaly, 1 = normal
    is_attack_true = (table["label"] != "Normal").to_numpy(dtype=bool)
    is_anomaly_pred = (preds == -1)
    acc = accuracy_score(is_attack_true, is_anomaly_pred)
    report["isolation_forest"] = {
        "accuracy_vs_attack_labels": round(acc, 4), "features": IF_FEATURES,
        "trained_on": "normal traffic only (unsupervised)", "n_normal_train": len(normal),
    }
    joblib.dump({"model": model, "scaler": scaler, "features": IF_FEATURES}, _path("isolation_forest.joblib"))
    return acc


# =====================================================================
# 6. K-MEANS — behavior clustering
# =====================================================================
def train_kmeans(table, report):
    X = table[KM_FEATURES].fillna(0).values
    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)
    k = 6
    model = KMeans(n_clusters=k, random_state=7, n_init=10).fit(Xs)
    sil = silhouette_score(Xs, model.labels_)

    # purity check: for each cluster, what's the dominant true label?
    tmp = table.copy()
    tmp["cluster"] = model.labels_
    purity_rows = []
    for c in range(k):
        sub = tmp[tmp["cluster"] == c]
        top_label = sub["label"].value_counts().idxmax()
        purity = (sub["label"] == top_label).mean()
        purity_rows.append({"cluster": int(c), "size": len(sub), "dominant_label": top_label, "purity": round(float(purity), 3)})
    report["kmeans"] = {"k": k, "silhouette_score": round(float(sil), 4), "features": KM_FEATURES, "clusters": purity_rows}
    joblib.dump({"model": model, "scaler": scaler, "features": KM_FEATURES}, _path("kmeans.joblib"))
    return sil


# =====================================================================
# TRAIN ALL + REPORT
# =====================================================================
def train_all(bad_ja3_hashes=None):
    bad_ja3_hashes = bad_ja3_hashes or set()
    table, traffic, labels = _load_training_table(bad_ja3_hashes)

    report = {}
    train_logistic_regression(table, report)
    train_decision_tree(table, report)
    train_random_forest(table, report)
    train_naive_bayes(traffic, report)
    train_isolation_forest(table, report)
    train_kmeans(table, report)

    with open(_path("training_report.json"), "w") as f:
        json.dump(report, f, indent=2)
    return report


# =====================================================================
# LIVE PREDICTION (loads saved models)
# =====================================================================
_loaded = {}


def _get(name):
    if name not in _loaded:
        _loaded[name] = joblib.load(_path(f"{name}.joblib"))
    return _loaded[name]


def predict_all(host_df, bad_ja3_hashes=None):
    """host_df: one host's traffic, already filtered. Returns a dict of
    predictions from all 6 models — meant to run alongside (not replace)
    the rule-based detection.run_all_checks for the same host."""
    bad_ja3_hashes = bad_ja3_hashes or set()
    feats = mf.extract_features(host_df, bad_ja3_hashes)
    out = {}

    lr = _get("logistic_regression")
    x = np.array([[feats[f] for f in lr["features"]]])
    prob = lr["model"].predict_proba(lr["scaler"].transform(x))[0][1]
    out["logistic_regression"] = {"flood_probability": round(float(prob), 3)}

    dt = _get("decision_tree")
    x = np.array([[feats[f] for f in dt["features"]]])
    out["decision_tree"] = {"predicted_label": dt["model"].predict(x)[0]}

    rf = _get("random_forest")
    x = np.array([[feats[f] for f in rf["features"]]])
    probs = rf["model"].predict_proba(x)[0]
    classes = rf["model"].classes_
    top_idx = int(np.argmax(probs))
    out["random_forest"] = {
        "predicted_label": classes[top_idx],
        "confidence": round(float(probs[top_idx]), 3),
        "all_probabilities": {c: round(float(p), 3) for c, p in zip(classes, probs)},
    }

    ifo = _get("isolation_forest")
    x = np.array([[feats[f] for f in ifo["features"]]])
    score = ifo["model"].decision_function(ifo["scaler"].transform(x))[0]
    is_anomaly = ifo["model"].predict(ifo["scaler"].transform(x))[0] == -1
    out["isolation_forest"] = {"is_anomaly": bool(is_anomaly), "anomaly_score": round(float(-score), 4)}

    km = _get("kmeans")
    x = np.array([[feats[f] for f in km["features"]]])
    cluster = int(km["model"].predict(km["scaler"].transform(x))[0])
    out["kmeans"] = {"cluster": cluster}

    out["features_used"] = feats
    return out


def predict_domain_naive_bayes(domain):
    nb = _get("naive_bayes")
    x = nb["vectorizer"].transform([domain])
    pred = nb["model"].predict(x)[0]
    prob = nb["model"].predict_proba(x)[0][1]
    return {"domain": domain, "looks_gibberish": bool(pred), "gibberish_probability": round(float(prob), 3)}
