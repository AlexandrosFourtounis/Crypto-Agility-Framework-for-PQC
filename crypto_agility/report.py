"""Export current findings and suggested migration work without modifying source."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from .config import DATABASE, DATA_DIR, RULES_DIR


def build_report(db_path, case_name):
    with open(RULES_DIR / "migration.json", encoding="utf-8") as stream:
        migration = json.load(stream)
    uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT file_path, line_start, check_id, message, severity, scan_date
            FROM semgrep_results
            WHERE scan_name=? AND check_id IS NOT NULL
            ORDER BY file_path, line_start, check_id
        """, (case_name,)).fetchall()
    findings = []
    for row in rows:
        finding = dict(row)
        entry = migration.get(row["check_id"], {})
        finding["algorithm"] = entry.get("algorithm")
        finding["suggested_replacement"] = entry.get("replacement")
        findings.append(finding)
    return {
        "case": case_name,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {
            "findings": len(findings),
            "files_with_findings": len({row["file_path"] for row in rows}),
            "by_severity": dict(Counter(row["severity"] for row in rows)),
            "by_extension": dict(Counter(Path(row["file_path"]).suffix for row in rows)),
            "with_suggested_replacement": sum(bool(f["suggested_replacement"]) for f in findings),
        },
        "note": "Suggestions require review. This report does not verify completed fixes or post-quantum security.",
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, help="Name of the saved scan case")
    parser.add_argument("--db", default=DATABASE, type=Path, help="SQLite findings database")
    parser.add_argument("--output", default=DATA_DIR / "migration-report.json", type=Path)
    args = parser.parse_args()
    try:
        report = build_report(args.db, args.case)
    except (OSError, sqlite3.Error) as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Exported {report['summary']['findings']} findings to {args.output}")


if __name__ == "__main__":
    main()
