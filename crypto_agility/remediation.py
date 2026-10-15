"""Apply source-edit templates to findings that have enough local context."""

import sqlite3
import yaml
import os
import logging
import re


from .config import DATABASE, REMEDIATION_RULES

FIXES_YAML = REMEDIATION_RULES
# Restrict automatic edits to expression replacements with known local context.
# Cipher and key-management changes remain assisted templates for manual review.
AUTOMATIC_FIXES = {
    "detect-md5", "detect-sha1", "detect-small-rsa",
    "detect-md5-java", "detect-sha1-java",
}

logging.basicConfig(level=logging.INFO)


def load_fixes():
    """Load fix snippets from fixes.yaml."""
    with open(FIXES_YAML, "r") as f:
        data = yaml.safe_load(f)
    fix_map = {}
    for rule in data.get("rules", []):
        cid = rule.get("id")
        fix_snippet = rule.get("fix", "")
        if cid and fix_snippet:
            fix_map[cid] = fix_snippet
    return fix_map


def get_vulnerability_by_id(vuln_id):
    """Return DB row for a single vulnerability ID."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""
        SELECT id, scan_name, file_path, line_start, check_id, message, column_start, column_end,line_end
        FROM semgrep_results
        WHERE id=?
    """, (vuln_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "scan_name": row[1],
        "file_path": row[2],
        "line_start": row[3],
        "check_id": row[4],
        "message": row[5],
        "column_start": row[6],
        "column_end": row[7],
        "line_end": row[8]
    }


PLACEHOLDER_PATTERNS = {
    "$DATA": re.compile(
        r"hashlib\.\w+\s*\(\s*(?P<data>.*?)\s*\)",
        re.DOTALL
    ),
    "$ARGS": re.compile(
        # Regex accepts:
        #   Crypto.Cipher.<algo>.new(...)
        #   DES.new(...)
        #   SHA1(...)
        #   DES_set_key(...)
        # capturing everything inside parentheses as group 'args'.
        r"(?:Crypto\.Cipher\.\w+\.new|DES|SHA1|DES_set_key)\s*\(\s*(?P<args>.*?)\s*\)",
        re.DOTALL
    ),
}


def apply_fix_to_file(file_path, line_start, column_start, line_end, column_end, fix_snippet):
    """Replace a stored source range; coordinates are 1-based with an inclusive end."""
    if not os.path.isfile(file_path):
        return "Source file is no longer available."
    with open(file_path, encoding="utf-8") as stream:
        lines = stream.readlines()
    if not (1 <= line_start <= line_end <= len(lines)):
        return "Source lines changed; re-scan before applying this template."
    first, last = lines[line_start - 1], lines[line_end - 1]
    if not (1 <= column_start <= len(first) and 1 <= column_end <= len(last)):
        return "Source columns changed; re-scan before applying this template."
    start = sum(map(len, lines[:line_start - 1])) + column_start - 1
    end = sum(map(len, lines[:line_end - 1])) + column_end
    if end < start:
        return "Invalid source range. Re-scan before applying this template."
    source = "".join(lines)
    removed = source[start:end]
    for placeholder, pattern in PLACEHOLDER_PATTERNS.items():
        if placeholder in fix_snippet:
            match = pattern.search(removed)
            if match:
                name = placeholder.strip("$").lower()
                fix_snippet = fix_snippet.replace(placeholder, match.group(name).strip())
    if re.search(r"\$[A-Z_]+", fix_snippet):
        return "The fix template needs context-specific values; review this finding manually."
    replacement = fix_snippet.rstrip("\n")
    with open(file_path, "w", encoding="utf-8") as stream:
        stream.write(source[:start] + replacement + source[end:])
    return "OK"


def fix_single_vulnerability(vuln_id):
    """Apply one template; the dashboard refreshes the scan afterward."""
    vuln = get_vulnerability_by_id(vuln_id)
    if not vuln:
        return {"status": "ERROR", "details": "No vulnerability found with that ID."}

    fix_map = load_fixes()
    snippet = fix_map.get(vuln["check_id"], "")
    if not snippet.strip():
        return {"status": "SUGGESTED", "details": "No direct fix snippet."}
    if vuln["check_id"] not in AUTOMATIC_FIXES:
        return {"status": "SUGGESTED", "details": f"Manual review required. Suggested template:\n{snippet}"}

    result = apply_fix_to_file(
        vuln["file_path"], vuln["line_start"], vuln["column_start"],
        vuln["line_end"], vuln["column_end"], snippet,
    )
    if result != "OK":
        return {"status": "SUGGESTED", "details": result}

    return {"status": "OK", "details": "Fix template applied. Review the edited source and re-scan results."}


def fix_all_in_case(case_name):
    """
    Fix all vulnerabilities in this case.
    Apply templates from the end of each file to preserve earlier source locations.
    """
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""
        SELECT id FROM semgrep_results
        WHERE scan_name=? AND check_id IS NOT NULL
        ORDER BY file_path, line_start DESC, column_start DESC
    """, (case_name,))
    vuln_ids = [r[0] for r in c.fetchall()]
    conn.close()

    fixed_count = 0
    suggested_count = 0

    for vid in vuln_ids:
        row_result = fix_single_vulnerability(vid)
        if row_result["status"] == "OK":
            fixed_count += 1
        elif row_result["status"] == "SUGGESTED":
            suggested_count += 1

    return {"fixed": fixed_count, "suggested": suggested_count}

