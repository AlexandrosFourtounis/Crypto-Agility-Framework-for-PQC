"""Local Flask dashboard for scan cases and assisted remediation."""

import os
import shutil
import sqlite3
import secrets
import tempfile
from datetime import datetime
from pathlib import Path
from flask import (
    Flask, render_template, request, redirect, url_for, flash, send_file
)
from io import BytesIO

from .config import DATABASE, CASES_DIR
from .remediation import fix_single_vulnerability, fix_all_in_case, get_vulnerability_by_id
from .scanner import create_database, load_rules, scan_directory, save_to_database
from .report import build_report
import json

app = Flask(__name__)
app.secret_key = os.environ.get("CRYPTO_AGILITY_SECRET_KEY") or secrets.token_hex(32)
app.config["UPLOAD_FOLDER"] = str(CASES_DIR)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024


def get_connection():
    return sqlite3.connect(DATABASE)


def create_main_table():
    """Initialize local storage, including a fresh checkout with no database."""
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    create_database(DATABASE)


def ensure_case_row_exists(case_name):
    """
    Insert an empty row if none exist for this case,
    so that 0-vulnerability cases still appear in the DB.
    """
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT 1 FROM semgrep_results WHERE scan_name=? LIMIT 1", (case_name,))
        row = c.fetchone()
        if not row:
            c.execute("""
                INSERT INTO semgrep_results (scan_name, scan_date)
                VALUES (?, NULL)
            """, (case_name,))
        conn.commit()


def list_cases():
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT
                scan_name,
                COUNT(check_id) AS total,
                SUM(CASE WHEN LOWER(severity)='info' THEN 1 ELSE 0 END) AS info_count,
                SUM(CASE WHEN LOWER(severity)='warning' THEN 1 ELSE 0 END) AS warning_count,
                SUM(CASE WHEN LOWER(severity)='error' THEN 1 ELSE 0 END) AS error_count,
                MAX(scan_date) AS last_scan
            FROM semgrep_results
            GROUP BY scan_name
            ORDER BY scan_name
        """)
        rows = c.fetchall()

    results = []
    for row in rows:
        scan_name, total, info, warning, error, last_scan = row
        results.append({
            "scan_name": scan_name,
            "total": int(total or 0),
            "info": int(info or 0),
            "warning": int(warning or 0),
            "error": int(error or 0),
            "last_scan": last_scan or ""
        })
    return results


def create_case(case_name):
    ensure_case_row_exists(case_name)


def delete_case(case_name):
    """Delete copied uploads only; CLI scan targets remain outside app ownership."""
    directory = get_scan_directory(case_name)
    if directory:
        path = Path(directory).resolve()
        uploads = Path(app.config["UPLOAD_FOLDER"]).resolve()
        if path.is_relative_to(uploads) and path != uploads and path.is_dir():
            shutil.rmtree(path)
    with get_connection() as conn:
        conn.execute("DELETE FROM semgrep_results WHERE scan_name=?", (case_name,))


def get_case_results(case_name):
    """
    Returns a list of vulnerabilities (plus ID),
    along with stats (info/warning/error),
    plus language counts.
    """
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT
                id,
                file_path,
                line_start,
                message,
                severity
            FROM semgrep_results
            WHERE scan_name=? AND check_id IS NOT NULL
        """, (case_name,))
        rows = c.fetchall()

        c.execute("""
            SELECT
              COUNT(check_id),
              SUM(CASE WHEN LOWER(severity)='info' THEN 1 ELSE 0 END),
              SUM(CASE WHEN LOWER(severity)='warning' THEN 1 ELSE 0 END),
              SUM(CASE WHEN LOWER(severity)='error' THEN 1 ELSE 0 END)
            FROM semgrep_results
            WHERE scan_name=?
        """, (case_name,))
        stat_row = c.fetchone()

    stats = {
        "total": int(stat_row[0] or 0),
        "info": int(stat_row[1] or 0),
        "warning": int(stat_row[2] or 0),
        "error": int(stat_row[3] or 0),
    }

    lang_counts = {"python": 0, "java": 0, "c": 0, "other": 0}
    row_list = []
    for (vuln_id, fpath, line, msg, sev) in rows:
        lower_fpath = (fpath or "").lower()
        if lower_fpath.endswith(".py"):
            lang_counts["python"] += 1
        elif lower_fpath.endswith(".java"):
            lang_counts["java"] += 1
        elif lower_fpath.endswith((".c", ".h")):
            lang_counts["c"] += 1
        elif fpath and fpath.strip():
            lang_counts["other"] += 1
        row_list.append((vuln_id, fpath, line, msg, sev))

    return row_list, stats, lang_counts


def clear_database():
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM semgrep_results")
        conn.commit()


def export_database():
    with open(DATABASE, "rb") as f:
        return BytesIO(f.read())


def import_database(file_stream):
    """Validate an imported database before replacing the local one."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=Path(DATABASE).parent, suffix=".db", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(file_stream.read())
        with sqlite3.connect(temporary) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(semgrep_results)")}
            required = {"id", "scan_name", "scan_date", "file_path", "line_start", "line_end",
                        "column_start", "column_end", "check_id", "message", "severity"}
            if not required.issubset(columns):
                raise ValueError("The database does not contain the expected findings table.")
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("The database failed its integrity check.")
        create_database(temporary)
        os.replace(temporary, DATABASE)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def scan_case(scan_name, target):
    """Scan first, then atomically replace the case's previous findings."""
    findings, _ = scan_directory(target, load_rules())
    save_to_database(findings, DATABASE, scan_name, datetime.now().isoformat(timespec="seconds"),
                     str(Path(target).resolve()))


def get_scan_directory(case_name):
    """
    Return the first non-null scan_directory for this scan_name, if any.
    """
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT scan_directory
            FROM semgrep_results
            WHERE scan_name=?
              AND scan_directory IS NOT NULL
            LIMIT 1
        """, (case_name,))
        row = c.fetchone()
        return row[0] if row else None


@app.route("/")
def index():
    cases = list_cases()
    return render_template("index.html", cases=cases)


@app.route("/create_case", methods=["POST"])
def handle_create_case():
    name = request.form.get("case_name", "").strip()
    if not name:
        flash("Case name cannot be empty!", "error")
        return redirect(url_for("index"))

    create_case(name)
    flash(f"Case '{name}' created (empty).", "success")
    return redirect(url_for("index"))


@app.route("/delete_case", methods=["POST"])
def handle_delete_case():
    name = request.form.get("case_name", "").strip()
    if name:
        delete_case(name)
        flash(f"Case '{name}' deleted.", "success")
    return redirect(url_for("index"))


@app.route("/load_case/<case_name>")
def load_case(case_name):
    rows, stats, lang_counts = get_case_results(case_name)
    low_count = stats["info"]
    med_count = stats["warning"]
    high_count = stats["error"]
    languages = list(lang_counts.keys())
    lang_values = list(lang_counts.values())

    return render_template(
        "case.html",
        case_name=case_name,
        rows=rows,
        stats=stats,
        low_count=low_count,
        med_count=med_count,
        high_count=high_count,
        languages=languages,
        lang_values=lang_values
    )


@app.route("/rescan_case", methods=["POST"])
def rescan_case():
    case_name = request.form.get("case_name", "").strip()
    directory = get_scan_directory(case_name)
    if not directory or not Path(directory).is_dir():
        flash("No saved source directory is available for this case.", "error")
        return redirect(url_for("index"))
    scan_case(case_name, directory)
    flash(f"Re-scan completed for '{case_name}'.", "success")
    return redirect(url_for("load_case", case_name=case_name))

@app.route("/scan_new_directory", methods=["POST"])
def scan_new_directory():
    """Save a directory upload inside owned case storage before scanning it."""
    name = request.form.get("new_case_name", "").strip()
    files = [file for file in request.files.getlist("new_target_path") if file.filename]
    if not name or name in {".", ".."} or any(char in name for char in "/\\"):
        flash("Use a case name without path separators.", "error")
        return redirect(url_for("index"))
    if not files:
        flash("Please select a directory to scan.", "error")
        return redirect(url_for("index"))
    uploads = Path(app.config["UPLOAD_FOLDER"]).resolve()
    case_dir = (uploads / name).resolve()
    if not case_dir.is_relative_to(uploads) or case_dir == uploads:
        flash("Invalid case directory.", "error")
        return redirect(url_for("index"))
    destinations = []
    for file in files:
        destination = (case_dir / file.filename.replace("\\", "/")).resolve()
        if not destination.is_relative_to(case_dir) or destination == case_dir:
            flash("Uploaded paths must stay inside the case directory.", "error")
            return redirect(url_for("index"))
        destinations.append((file, destination))
    existing = get_scan_directory(name)
    if existing and Path(existing).resolve() != case_dir:
        flash("That case already refers to a different source directory. Use a new name.", "error")
        return redirect(url_for("index"))
    for file, destination in destinations:
        destination.parent.mkdir(parents=True, exist_ok=True)
        file.save(destination)
    scan_case(name, case_dir)
    flash(f"Scanned uploaded directory into case '{name}'.", "success")
    return redirect(url_for("load_case", case_name=name))


@app.route("/clear_db", methods=["POST"])
def do_clear_db():
    clear_database()
    flash("Database cleared.", "success")
    return redirect(url_for("index"))


@app.route("/export_db", methods=["GET"])
def do_export_db():
    mem = export_database()
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name="findings.db")


@app.route("/import_db", methods=["POST"])
def do_import_db():
    f = request.files.get("dbfile")
    if not f or f.filename == "":
        flash("No .db file provided.", "error")
        return redirect(url_for("index"))
    try:
        import_database(f)
    except (sqlite3.Error, ValueError):
        flash("Please provide a valid exported findings database.", "error")
        return redirect(url_for("index"))
    flash("Database imported successfully.", "success")
    return redirect(url_for("index"))


@app.route("/fix_vulnerability", methods=["POST"])
def fix_vulnerability():
    vuln_id = request.form.get("vuln_id", type=int)
    case_name = request.form.get("case_name", "")
    finding = get_vulnerability_by_id(vuln_id) if vuln_id else None
    if not finding or finding["scan_name"] != case_name:
        flash("The finding does not belong to this case.", "error")
        return redirect(url_for("index"))
    result = fix_single_vulnerability(vuln_id)
    if result["status"] == "OK":
        directory = get_scan_directory(case_name)
        if directory:
            scan_case(case_name, directory)
    flash(result["details"], "info")
    return redirect(url_for("load_case", case_name=case_name))


@app.route("/fix_all_vulnerabilities", methods=["POST"])
def fix_all_vulnerabilities():
    case_name = request.form.get("case_name", "").strip()
    if not case_name:
        flash("Missing case name.", "error")
        return redirect(url_for("index"))
    result = fix_all_in_case(case_name)
    directory = get_scan_directory(case_name)
    if directory:
        scan_case(case_name, directory)
    flash(f"Applied {result['fixed']} templates; {result['suggested']} findings need manual review. "
          "Review the edited source and re-scan results.", "info")
    return redirect(url_for("load_case", case_name=case_name))


@app.route("/report/<case_name>")
def download_report(case_name):
    report = build_report(DATABASE, case_name)
    data = BytesIO(json.dumps(report, indent=2).encode("utf-8"))
    return send_file(data, as_attachment=True, download_name="migration-report.json", mimetype="application/json")


create_main_table()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
