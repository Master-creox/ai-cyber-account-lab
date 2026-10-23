"""Run the Isolation Forest experiment: python scripts/run_isolation_forest.py

Prints both evaluations:
  1. in-sample (optimistic - detectors see their own training normals)
  2. strict held-out split (honest - test data never seen during fitting)
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.isolation_forest_experiment import run_experiment, run_experiment_strict

if __name__ == "__main__":
    print("== In-sample evaluation (optimistic) ==")
    print(json.dumps(run_experiment(), indent=2))
    print("\n== Strict held-out evaluation (honest) ==")
    print(json.dumps(run_experiment_strict(), indent=2))
