# Development notes

## Components

`crypto_agility.scanner` reads `rules/detection.yaml`, scans supported source files, and optionally stores findings in SQLite. `crypto_agility.web` uses the same scanner directly, manages cases, and refreshes stored findings after remediation. `crypto_agility.remediation` applies selected source-edit templates from `rules/remediation.yaml`. `crypto_agility.report` joins saved findings with `rules/migration.json` to export review work.

Findings retain the original `semgrep_results` table name for compatibility with earlier project databases. Each case stores its latest scan snapshot. 

## Local configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `CRYPTO_AGILITY_DATA_DIR` | `<repo>/instance` | Dashboard database, uploaded case copies, and default report location |
| `CRYPTO_AGILITY_SECRET_KEY` | Random per process | Optional persistent Flask session secret |

The dashboard binds to `127.0.0.1:5000`, with debug mode disabled. It is intended for trusted local use and has no authentication or multi-user isolation. Uploads are limited to 32 MiB per request. 

Directory uploads are copied under `instance/cases/`. CLI scans retain the paths of their original files; dashboard fixes to those cases edit those files directly. Deleting a case removes copied uploads only when the directory is inside the configured upload folder. Clearing the database leaves copied source directories in place. Imported databases should come from trusted local exports because they contain source paths used for editing.

## Detection and remediation limits

- The internal engine supports a subset of Semgrep-style patterns, numeric metavariables, and rule conditions. It does not implement Semgrep's syntax-tree or data-flow semantics.
- Each rule reports its first match in each file. Comments, string literals, formatting changes, aliases, and nested expressions can cause false positives, missed matches, or approximate source ranges.
- File extensions select Python, Java, or C rules (`.h` uses C rules). Virtual environments, Git metadata, and common dependency/cache directories are excluded.
- Rule conditions are evaluated as Python expressions with restricted globals. Rule files are trusted project configuration, not an input sandbox; do not load untrusted rules.
- Automatic edits are limited to Python MD5/SHA-1 expressions, literal `RSA.generate` key sizes, and Java MD5/SHA-1 `MessageDigest` expressions. Other templates are displayed for manual review. Changing a primitive may affect protocols, stored data, signatures, or API behavior.
- Source ranges belong to the saved scan. Re-scan after editing source outside the dashboard, and inspect every generated change. Batch edits run from the end of each file to preserve earlier locations.
- SHA-256 and the prototype's AES key-size migration targets are inventory/review findings. They are not blanket claims that those algorithms are broken. The JSON report lists suggestions and does not count a suggestion as a completed fix.

The optional `--external --rules rules/semgrep.yaml` scanner path retains the original experimental Semgrep integration. It requires a separately installed `semgrep` executable. 

## Verification

Run `python -m unittest discover -s tests -v` from the repository root. Tests use temporary databases and source copies to cover language filtering, key-size boundaries, uploads, path containment, empty cases, individual and batch edits, re-scanning, reporting, and database import/export.
