# Crypto Agility Framework for PQC

A collaborative project prototype for finding insecure cryptographic usage in **Python, Java, and C** and tracking remediation through a **Flask + SQLite** dashboard. It combines rule-based source scanning, automated and assisted fixes, re-scanning, and JSON reporting to support cryptographic migration planning.

## Features

- **Source scanning:** YAML rules identify patterns associated with weak primitives, unsafe configurations, small RSA keys, and hardcoded keys or secrets.
- **Case management:** Upload a source directory, review findings by file and line, filter by language or severity, and import or export the findings database.
- **Remediation:** Apply selected hash and RSA key-size replacements automatically; review suggested templates for changes that require application context. Re-scanning refreshes the case after edits.
- **Migration reporting:** Export current findings, affected-file counts, severity breakdowns, and suggested replacements as JSON.

**Stack:** Python · Flask · SQLite · PyYAML · Bootstrap · Chart.js

## Quick start

Requires **Python 3.10+**. Run from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m crypto_agility.web
```

Open [localhost:5000](http://localhost:5000), enter a case name, and upload [`examples/vulnerable`](examples/vulnerable) using **Scan New Directory**. Open the case to inspect findings, try a fix, re-scan, or export a report. Uploaded source copies and the database are stored locally in `instance/`, which Git ignores.

On Windows, activate the environment with `.venv\Scripts\Activate.ps1`.

## Command-line demo

Scan the included fixtures and save a case that also appears in the dashboard:

```bash
python -m crypto_agility.scanner \
  --target examples/vulnerable \
  --db instance/findings.db \
  --scan-name demo

python -m crypto_agility.report \
  --case demo \
  --output instance/migration-report.json
```

Omit `--db` for a read-only console scan. Saving under an existing case name replaces its previous findings. CLI cases retain their original source paths; use a working copy before applying fixes to them in the dashboard.

## Repository layout

```text
crypto_agility/      Scanner, Flask dashboard, remediation, and reporting
rules/              Detection rules, fix templates, and migration mappings
examples/vulnerable/ Intentionally insecure Python, Java, and C fixtures
tests/              Scanner and case-workflow regression checks
docs/               Development notes and original research/report material
```

## Scope

This is a **local research prototype**. Its scanner uses text patterns rather than full language parsing or data-flow analysis; findings and edits require review and application tests. Some rules inventory cryptographic usage for assessment rather than identify a confirmed vulnerability. The supplied fixtures are intentionally insecure.

The project supports preparation for PQC migration. It does **not** implement post-quantum algorithms or establish quantum resistance. Increasing RSA key sizes or switching to ECDSA does not provide post-quantum security. See [NIST's migration FAQ](https://www.nccoe.nist.gov/migration-post-quantum-cryptography-faq) for context.

## Development

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs the checks on Python 3.10–3.12. See [development notes](docs/development.md) for configuration and scanner limitations, and [project material](docs/README.md) for the original reports.
