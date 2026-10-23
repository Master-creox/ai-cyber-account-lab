# Experiment: Isolation Forest vs Statistical Detector

## Question
Does scikit-learn's **Isolation Forest** detect anomalous logins better than
this lab's dependency-free statistical (z-score) detector?

## Setup
- **Data:** the lab's synthetic dataset — 230 logins (200 normal, 30 anomalous),
  generated with seed 42 by `src/ai_anomaly.generate_synthetic_logins`.
  No real user data is used.
- **Features (same for both detectors):** new country, new device, distance
  from the usual login hour, deep-night login, failed attempts — see
  `featurize()` in `src/ai_anomaly.py`.
- **Training:** both detectors are fitted on the 200 *normal* logins only —
  the realistic setting, where labelled attacks are rare.
- **Code:** `src/isolation_forest_experiment.py`
- **Run it:**
  ```bash
  pip install -r requirements-ml.txt
  python scripts/run_isolation_forest.py
  ```
  Tested with scikit-learn 1.9.1.

## Results (contamination = 0.02, 200 trees)

| Detector | Accuracy | Anomalies caught | Missed | False alarms | Recall | Precision |
|---|---|---|---|---|---|---|
| Statistical (z-score) | 98.3% | 26 / 30 | 4 | 0 | 86.7% | 100% |
| **Isolation Forest** | **99.1%** | **30 / 30** | **0** | 2 | **100%** | 93.8% |

## Sensitivity: the `contamination` setting matters
`contamination` is the expected share of anomalies the model is told to
flag. Sweeping it changed the trade-off a lot:

| Contamination | Accuracy | Anomalies caught | False alarms |
|---|---|---|---|
| 0.01 | 99.1% | 30 / 30 | 2 |
| **0.02 (chosen default)** | **99.1%** | **30 / 30** | **2** |
| 0.05 | 95.7% | 30 / 30 | 10 |
| 0.10 | 93.0% | 30 / 30 | 16 |

Higher contamination catches the same attacks but flags many more normal
logins — in a real product that means annoying innocent users with
challenges and alerts.

## Conclusion
On this synthetic data, a tuned Isolation Forest is the stronger detector:
it missed **no** attacks, at the cost of 2 false alarms, while the
statistical detector never false-alarms but misses 4 attacks. For account
security, missing an attack is usually worse than an extra verification
challenge — so the Forest is the better default *when scikit-learn is
available*, and the statistical detector remains a solid zero-dependency
fallback.

## Limitations (read before quoting these numbers)
- The data is **synthetic and simple**; real logins are noisier and
  attackers adapt. These scores will not transfer directly to real traffic.
- Detectors are evaluated on the full synthetic set, which includes the
  normal logins they were trained on, so results are optimistic.
  A strict train/test split is the obvious next step.
- Features are account-profile relative (usual country/device/hours);
  a production system needs per-account baselines and privacy review.
