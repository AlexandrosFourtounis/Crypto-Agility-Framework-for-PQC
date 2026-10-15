"""Heuristic source scanner with YAML rules and optional SQLite persistence."""

import os
import re
import sys
import argparse
import sqlite3
import logging
import yaml
import json
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .config import DETECTION_RULES

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


# --- Database Functions ---
def create_database(db_file, reset=False):
    """Create (or reset) the SQLite database and table for scan results."""
    Path(db_file).resolve().parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    if reset:
        cursor.execute("DROP TABLE IF EXISTS semgrep_results")
        logging.info("Database reset: Existing table dropped.")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS semgrep_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_name TEXT,
            scan_date TEXT,
            file_path TEXT,
            line_start INTEGER,
            line_end INTEGER,
            column_start INTEGER,
            column_end INTEGER,
            check_id TEXT,
            message TEXT,
            severity TEXT,
            scan_directory TEXT
        )
    """)
    columns = {row[1] for row in cursor.execute("PRAGMA table_info(semgrep_results)")}
    if "scan_directory" not in columns:
        cursor.execute("ALTER TABLE semgrep_results ADD COLUMN scan_directory TEXT")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_path ON semgrep_results(file_path)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON semgrep_results(severity)")
    conn.commit()
    conn.close()


def save_to_database(findings, db_file, scan_name, scan_date, scan_directory=None):
    """Atomically replace a case with its latest findings, including empty scans."""
    with sqlite3.connect(db_file) as conn:
        conn.execute("DELETE FROM semgrep_results WHERE scan_name=?", (scan_name,))
        seen = set()
        for finding in findings:
            start, end = finding.get("start", {}), finding.get("end", {})
            extra = finding.get("extra", {})
            signature = (finding.get("path"), start.get("line"), finding.get("check_id"))
            if signature in seen:
                continue
            seen.add(signature)
            conn.execute("""
                INSERT INTO semgrep_results (
                    scan_name, scan_date, file_path, line_start, line_end,
                    column_start, column_end, check_id, message, severity, scan_directory
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_name, scan_date, finding.get("path"), start.get("line"),
                  end.get("line"), start.get("col", 0), end.get("col", 0) - 1,
                  finding.get("check_id"), extra.get("message"), extra.get("severity"),
                  scan_directory))
        if not findings:
            conn.execute("""
                INSERT INTO semgrep_results (scan_name, scan_date, scan_directory)
                VALUES (?, ?, ?)
            """, (scan_name, scan_date, scan_directory))


# --- File and Language Helpers ---
def gather_all_files(target_path):
    """Collect supported source files, excluding local tooling and Git metadata."""
    target = Path(target_path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Scan target does not exist: {target}")
    if target.is_file():
        return [str(target)] if get_language_from_extension(str(target)) != "unknown" else []
    excluded = {".git", ".venv", "venv", "__pycache__", "node_modules", ".idea"}
    paths = []
    for directory, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in excluded and not d.endswith("-env"))
        for name in sorted(files):
            path = Path(directory) / name
            if not path.is_symlink() and get_language_from_extension(str(path)) != "unknown":
                paths.append(str(path))
    return paths


def get_language_from_extension(file_path):
    """Naively determine the language based on file extension."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.py':
        return 'python'
    elif ext == '.java':
        return 'java'
    elif ext in ['.c', '.h']:
        return 'c'
    else:
        return 'unknown'


# --- Pattern Conversion Helper ---
def pattern_to_regex(pattern: str) -> str:
    """
    Convert a Semgrep‑style pattern to a regex.
      - Replace '...' with a non‑greedy wildcard (.*?)
      - Replace metavariables (e.g. $X, $SIZE) with named capturing groups that match digits.
      - Escape all other characters.
    """
    placeholder_wild = "__WILDCARD__"
    pattern = pattern.replace("...", placeholder_wild)

    def replace_metavar(match):
        varname = match.group(0)[1:]
        return f"__VAR_{varname}__"

    pattern = re.sub(r'\$[A-Za-z_]+', replace_metavar, pattern)
    pattern = re.escape(pattern)
    pattern = pattern.replace(re.escape(placeholder_wild), ".*?")
    pattern = re.sub(r'\\s\\\*', lambda m: r'\s*', pattern)

    def revert_metavar(match):
        varname = match.group(1)
        return r"(?P<%s>\d+)" % varname

    pattern = re.sub(r'__VAR_([A-Za-z_]+)__', revert_metavar, pattern)
    return pattern


# --- Rule Loading ---
def load_rules(rule_file=DETECTION_RULES):
    """Load the internal scanner's rule definitions."""
    with open(rule_file, encoding="utf-8") as stream:
        return yaml.safe_load(stream).get("rules", [])


# --- A Helper Class for Captured Variables in pattern-where Evaluations ---
class Captured:
    def __init__(self, value):
        self.value = int(value) if value.isdigit() else value
        self.constant = value.isdigit()


# --- Scanning Functions (Internal Engine) ---
def scan_code(code_text: str, rules: list) -> list:
    """
    Scan the provided code text using the given rules.
    Returns a list of findings with rule id, message, severity, and an approximate
    line and column numbers. Supports 'pattern', 'patterns', 'pattern-inside',
    and 'pattern-where-python'.
    """
    findings = []
    for rule in rules:
        rule_matched = True
        cap_vars = {}  # Dictionary to store captured metavariables

        # Handle a single "pattern" field
        if "pattern" in rule:
            pat = rule["pattern"]
            if rule.get("raw", False):
                regex_pat = re.compile(pat, re.DOTALL)
            else:
                regex_pat = re.compile(pattern_to_regex(pat), re.DOTALL)
            m = regex_pat.search(code_text)
            if not m:
                rule_matched = False
            else:
                # If there are no named groups but capturing groups exist, store first group as $X
                if not m.groupdict() and m.groups():
                    cap_vars.setdefault("$X", []).append(m.group(1))
                else:
                    for var, val in m.groupdict().items():
                        cap_vars.setdefault("$" + var, []).append(val)
        # Handle "patterns" list
        elif "patterns" in rule:
            for item in rule["patterns"]:
                if "pattern" in item:
                    pat = item["pattern"]
                    if rule.get("raw", False):
                        regex_pat = re.compile(pat, re.DOTALL)
                    else:
                        regex_pat = re.compile(pattern_to_regex(pat), re.DOTALL)
                    m = regex_pat.search(code_text)
                    if not m:
                        rule_matched = False
                        break
                    if not m.groupdict() and m.groups():
                        cap_vars.setdefault("$X", []).append(m.group(1))
                    else:
                        for var, val in m.groupdict().items():
                            cap_vars.setdefault("$" + var, []).append(val)
                elif "pattern-inside" in item:
                    pat_inside = item["pattern-inside"]
                    regex_pat = re.compile(pattern_to_regex(pat_inside), re.DOTALL)
                    m = regex_pat.search(code_text)
                    if not m:
                        rule_matched = False
                        break
                elif "metavariable-comparison" in item:
                    comp = item["metavariable-comparison"]
                    var = comp["metavariable"]
                    if var not in cap_vars or not cap_vars[var]:
                        rule_matched = False
                        break
                    valid = False
                    for val in cap_vars[var]:
                        try:
                            expr = comp["comparison"].replace("$X.value", str(val))
                            if eval(expr, {"__builtins__": {}}):
                                valid = True
                                break
                        except Exception:
                            pass
                    if not valid:
                        rule_matched = False
                        break
        else:
            rule_matched = False

        # Evaluate top-level pattern-where-python if present.
        if rule_matched and "pattern-where-python" in rule:
            expr = rule["pattern-where-python"]
            local_vars = {"vars": {}}
            for key, vals in cap_vars.items():
                local_vars["vars"][key[1:]] = Captured(vals[0])
            try:
                if not eval(expr, {"__builtins__": {"int": int, "isinstance": isinstance}}, local_vars):
                    rule_matched = False
            except Exception:
                rule_matched = False

        if rule_matched:
            start_line = -1
            start_col = -1
            end_line = -1
            end_col = -1
            match_found = None

            if "pattern" in rule:
                if rule.get("raw", False):
                    regex_pat = re.compile(rule["pattern"], re.DOTALL)
                else:
                    regex_pat = re.compile(pattern_to_regex(rule["pattern"]), re.DOTALL)
                match_found = regex_pat.search(code_text)
            elif "patterns" in rule:
                for item in rule["patterns"]:
                    if "pattern" in item:
                        pattern = item["pattern"] if rule.get("raw", False) else pattern_to_regex(item["pattern"])
                        regex_pat = re.compile(pattern, re.DOTALL)
                        match_found = regex_pat.search(code_text)
                        if match_found:
                            break

            if match_found:
                start_line = code_text[:match_found.start()].count("\n") + 1
                last_newline = code_text.rfind("\n", 0, match_found.start())
                if last_newline == -1:
                    start_col = match_found.start() + 1
                else:
                    start_col = match_found.start() - last_newline
                end_line = code_text[:match_found.end()].count("\n") + 1
                last_newline_end = code_text.rfind("\n", 0, match_found.end())
                if last_newline_end == -1:
                    end_col = match_found.end() + 1
                else:
                    end_col = match_found.end() - last_newline_end

            findings.append({
                "check_id": rule.get("id"),
                "start": {"line": start_line, "col": start_col},
                "end": {"line": end_line, "col": end_col},
                "extra": {"message": rule.get("message"), "severity": rule.get("severity")}
            })
    return findings


def scan_file(file_path: str, rules: list) -> list:
    """Read a file and scan its content using the vulnerability rules. Returns findings with file path added."""
    try:
        with open(file_path, "r", errors="ignore") as f:
            code_text = f.read()
    except Exception as e:
        logging.warning(f"Error reading file {file_path}: {e}")
        return []
    language = get_language_from_extension(str(file_path))
    findings = scan_code(code_text, [rule for rule in rules if language in rule.get("languages", [])])
    for finding in findings:
        finding["path"] = file_path
    return findings


def scan_directory(target: str, rules: list) -> tuple[list, list]:
    """Scan all files under the target (directory or file) and return findings and the file list."""
    all_files = gather_all_files(target)
    all_findings = []
    for file_path in all_files:
        file_findings = scan_file(file_path, rules)
        if file_findings:
            logging.debug(f"Found {len(file_findings)} issues in {file_path}")
        all_findings.extend(file_findings)
    return all_findings, all_files


def display_findings(findings: list, all_files: list):
    """
    Produce a detailed report of vulnerabilities along with a summary.
    The summary lists, for each language, the number of vulnerable files and a list (just the filename) of vulnerable files.
    """
    if not findings:
        print("\nNo matching findings.\n")
        return
    print("\n=== Cryptographic Findings ===\n")
    for i, finding in enumerate(findings, start=1):
        print(f"Finding #{i}:")
        print(f"  Rule       : {finding.get('check_id')}")
        print(f"  File       : {finding.get('path')}")
        start = finding.get("start", {})
        print(f"  Start Line : {start.get('line')}, Column: {start.get('col')}")
        end = finding.get("end", {})
        print(f"  End Line   : {end.get('line')}, Column: {end.get('col')}")
        extra = finding.get("extra", {})
        print(f"  Severity   : {extra.get('severity')}")
        print(f"  Message    : {extra.get('message')}\n")
    file_stats = defaultdict(lambda: {"total": 0, "vulnerable": 0, "vul_files": set()})
    for file_path in all_files:
        lang = get_language_from_extension(file_path)
        file_stats[lang]["total"] += 1
    for finding in findings:
        file_path = finding.get("path")
        lang = get_language_from_extension(file_path)
        file_stats[lang]["vulnerable"] += 1
        file_stats[lang]["vul_files"].add(os.path.basename(file_path))
    print("=== Scan Summary ===")
    for lang, stats in file_stats.items():
        vul_list = sorted(stats["vul_files"])
        print(f"  {lang.capitalize()}: {stats['vulnerable']} findings across {stats['total']} source files {vul_list}")
    print("")


# --- External Semgrep Runner (Optional Mode) ---
def run_semgrep(rule_file, target):
    """
    Run Semgrep on a target file/directory with a specific rule file.
    Captures findings from Semgrep JSON output.
    """
    if not os.path.exists(rule_file):
        raise FileNotFoundError(f"Rule file not found: {rule_file}")
    try:
        result = subprocess.run(
            ["semgrep", "--config", rule_file, target, "--json"],
            capture_output=True,
            text=True,
            check=True
        )
        findings = json.loads(result.stdout)
        return findings.get("results", [])
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running Semgrep: {e.stderr}")
        raise RuntimeError("External Semgrep scan failed") from e


# --- Main Program ---
def main():
    parser = argparse.ArgumentParser(
        description="Scan a directory (or file) for vulnerabilities using YAML pattern rules."
    )
    parser.add_argument("--target", help="Path to the target directory or file")
    parser.add_argument("--rules",
                        help="Path to an external Semgrep-like rules file. "
                             "If omitted, rules/detection.yaml is used.",
                        default=None)
    parser.add_argument("--db", help="Path to the SQLite DB file. If omitted, results are not saved to a DB.",
                        default=None)
    parser.add_argument("--reset-db", help="Reset the database before saving", action="store_true")
    parser.add_argument("--external", help="Use external Semgrep (via subprocess) instead of the internal scanner",
                        action="store_true")
    parser.add_argument("--scan-name", help="Case name for SQLite persistence (otherwise prompted)")
    args = parser.parse_args()

    # Prompt for target if not provided
    if not args.target:
        args.target = input("Enter the path to the target file/folder to scan: ").strip()

    # For external mode, prompt for rules file if not provided
    if args.external and not args.rules:
        args.rules = input("Enter the path to your Semgrep rules file: ").strip()

    if not Path(args.target).exists():
        parser.error(f"Scan target does not exist: {args.target}")

    # Determine scanning method
    if args.external:
        findings = run_semgrep(args.rules, args.target)
        all_files = gather_all_files(args.target)
    else:
        if args.rules:
            try:
                with open(args.rules, "r") as f:
                    rules_data = yaml.safe_load(f)
                rules = rules_data.get("rules", [])
            except Exception as e:
                logging.error(f"Error reading rules file {args.rules}: {e}")
                sys.exit(1)
        else:
            rules = load_rules()
        findings, all_files = scan_directory(args.target, rules)

    display_findings(findings, all_files)

    # Database export (only if the --db flag was provided)
    if args.db:
        scan_name = args.scan_name or input("Enter a name for this scan: ").strip()
        if not scan_name:
            scan_name = "Unnamed_Scan"
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        create_database(args.db, reset=args.reset_db)
        save_to_database(findings, args.db, scan_name, scan_date, str(Path(args.target).resolve()))
        logging.info(f"Results saved to database '{args.db}' (scan: '{scan_name}', date: {scan_date}).")


if __name__ == "__main__":
    main()
