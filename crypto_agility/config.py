"""Shared paths for the CLI, dashboard, and remediation helpers."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
DATA_DIR = Path(os.environ.get("CRYPTO_AGILITY_DATA_DIR", ROOT / "instance")).expanduser().resolve()
DATABASE = DATA_DIR / "findings.db"
CASES_DIR = DATA_DIR / "cases"
DETECTION_RULES = RULES_DIR / "detection.yaml"
REMEDIATION_RULES = RULES_DIR / "remediation.yaml"
