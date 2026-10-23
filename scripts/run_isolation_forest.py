"""Run the Isolation Forest experiment: python scripts/run_isolation_forest.py"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.isolation_forest_experiment import run_experiment

if __name__ == "__main__":
    print(json.dumps(run_experiment(), indent=2))
