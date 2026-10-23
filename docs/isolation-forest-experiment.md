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

## Strict held-out evaluation (the honest numbers)

The table above is *in-sample*: the detectors were evaluated on data that
included their own training logins, which flatters them. The strict
version (`run_experiment_strict()`) splits the 200 normal logins 70/30
**before** fitting — 140 train, 60 held out — and evaluates only on the
held-out 60 normals plus all 30 anomalies (anomalies are never trained on):

| Detector | Accuracy | Anomalies caught | False alarms |
|----------|----------|------------------|--------------|
| Statistical (z-score) | **100%** | 30 / 30 | 0 |
| Isolation Forest (contamination 0.02) | 98.9% | 30 / 30 | 1 |

On held-out data the gap disappears — both detectors catch every attack,
and the simple statistical detector actually edges ahead with zero false
alarms. The in-sample "Forest wins" result was partly an artefact of the
evaluation method, which is exactly why held-out evaluation matters.

## Conclusion
On this synthetic data both detectors are strong. In-sample, a tuned
Isolation Forest looks better (no missed attacks, 2 false alarms vs the
statistical detector's 4 misses). On a strict held-out split they tie on
detection and the zero-dependency statistical detector wins on false
alarms. For account security, missing an attack is usually worse than an
extra verification challenge — but the honest takeaway is that evaluation
method changes the ranking, so quote the held-out numbers.

## Limitations (read before quoting these numbers)
- The data is **synthetic and simple**; real logins are noisier and
  attackers adapt. These scores will not transfer directly to real traffic.
- The in-sample table at the top is optimistic by construction; the
  strict held-out table above is the one to quote.
- Features are account-profile relative (usual country/device/hours);
  a production system needs per-account baselines and privacy review.
