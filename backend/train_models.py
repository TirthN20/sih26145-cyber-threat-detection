"""
TRAIN ALL 6 MODELS
====================================================
Run this after ml_training_data.py has produced
ml_training_traffic.csv / ml_training_labels.csv.

Usage:
    python3 ml_training_data.py     (once, or to regenerate training data)
    python3 train_models.py

Saves trained models to backend/models/*.joblib and prints an honest
evaluation for each one (accuracy on a held-out test set it never
trained on) — not just "it works," actual numbers.
"""

import json
import ml_models as mm

KNOWN_BAD_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865",
    "6734f37431670b3ab4292b8f60f29984",
}


def main():
    print("Training all 6 models on ml_training_traffic.csv / ml_training_labels.csv ...\n")
    report = mm.train_all(bad_ja3_hashes=KNOWN_BAD_JA3)

    print("=" * 70)
    print("1. LOGISTIC REGRESSION  (Flood/DoS probability)")
    print(f"   Accuracy: {report['logistic_regression']['accuracy']*100:.1f}%  "
          f"(tested on {report['logistic_regression']['test_size']} held-out hosts)")
    print(f"   Features: {report['logistic_regression']['features']}")

    print("\n" + "=" * 70)
    print("2. DECISION TREE  (Normal / Flood / Scan)")
    print(f"   Accuracy: {report['decision_tree']['accuracy']*100:.1f}%  "
          f"(tested on {report['decision_tree']['test_size']} held-out hosts)")
    print(f"   Tree depth: {report['decision_tree']['tree_depth']}")

    print("\n" + "=" * 70)
    print("3. RANDOM FOREST  (main multi-class classifier, all 6 categories)")
    print(f"   Accuracy: {report['random_forest']['accuracy']*100:.1f}%  "
          f"(tested on {report['random_forest']['test_size']} held-out hosts)")
    print("   Feature importances:")
    for feat, imp in sorted(report['random_forest']['feature_importances'].items(), key=lambda x: -x[1]):
        print(f"     {feat:<28} {imp:.3f}")

    print("\n" + "=" * 70)
    print("4. NAIVE BAYES  (real-looking vs gibberish domain names)")
    print(f"   Accuracy: {report['naive_bayes']['accuracy']*100:.1f}%  "
          f"(tested on {report['naive_bayes']['test_size']} held-out domains, "
          f"{report['naive_bayes']['training_domains']} total)")

    print("\n" + "=" * 70)
    print("5. ISOLATION FOREST  (unsupervised anomaly detector)")
    print(f"   Accuracy vs true attack/normal labels: {report['isolation_forest']['accuracy_vs_attack_labels']*100:.1f}%")
    print(f"   (trained on {report['isolation_forest']['n_normal_train']} NORMAL hosts only, "
          f"never shown a single attack example)")

    print("\n" + "=" * 70)
    print("6. K-MEANS  (behavior clustering, k=6)")
    print(f"   Silhouette score: {report['kmeans']['silhouette_score']:.3f} (higher = better-separated clusters)")
    for c in report['kmeans']['clusters']:
        print(f"     cluster {c['cluster']}: {c['size']:>3} hosts, "
              f"dominant label = {c['dominant_label']:<45} purity={c['purity']}")

    print("\n" + "=" * 70)
    print("Full report saved to backend/models/training_report.json")


if __name__ == "__main__":
    main()
