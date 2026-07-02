"""
scan_state.py — Merge new scan results with previous report to maintain state.

Statuses: new, open, resolved, blocked, reopened (user can set open/resolved/blocked/reopened via UI).

When the same repo(s) are scanned again:
- Findings still present → keep "blocked"/"reopened" if set, else "open"; preserve first_seen
- New findings → status "new" (first_seen = now)
- Findings that were in previous but not in new scan → "resolved" (resolved_at = now), unless
  user had set "blocked" (then keep "blocked")

Storage: single JSON file (vulnerability_report_live_verified.json). No DB required.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# Maximum number of resolved entries to keep in the report (oldest dropped when over limit)
MAX_RESOLVED_ENTRIES = 500


def _finding_key(entry: Dict[str, Any]) -> tuple:
    """Stable key for a finding: (library, version_in_use, file_location)."""
    return (
        entry.get("library") or "",
        entry.get("version_in_use") or "",
        entry.get("file_location") or "",
    )


def _load_previous_report(report_path: Path) -> List[Dict[str, Any]]:
    """Load previous report if it exists; return empty list otherwise."""
    if not report_path.exists():
        return []
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError) as e:
        logging.warning(f"scan_state: could not load previous report from {report_path}: {e}")
        return []


def merge_with_previous(
    new_report: List[Dict[str, Any]],
    report_path: Path,
    max_resolved: int = MAX_RESOLVED_ENTRIES,
) -> List[Dict[str, Any]]:
    """
    Merge new scan results with the previous report.

    - Each entry in new_report gets status "new" or "open" and first_seen set.
    - Entries that were in the previous report but not in new_report get status "resolved"
      and resolved_at set, and are appended (up to max_resolved).

    Returns the merged list (new/open first, then resolved).
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    previous = _load_previous_report(report_path)

    # All previous entries by key (last occurrence wins); skip already-resolved for "disappeared" list
    prev_by_key: Dict[tuple, Dict[str, Any]] = {}
    for entry in previous:
        k = _finding_key(entry)
        prev_by_key[k] = entry

    new_keys = {_finding_key(e) for e in new_report}

    # User-set statuses that we preserve when the finding is still in the new scan
    USER_PRESERVED_STATUSES = ("blocked", "reopened")

    # Build merged: new/open/blocked/reopened with status and first_seen
    merged: List[Dict[str, Any]] = []
    for entry in new_report:
        row = dict(entry)
        k = _finding_key(entry)
        if k in prev_by_key:
            prev = prev_by_key[k]
            prev_status = prev.get("status") or "open"
            if prev_status in USER_PRESERVED_STATUSES:
                row["status"] = prev_status
            else:
                row["status"] = "open"
            row["first_seen"] = prev.get("first_seen") or now_iso
        else:
            row["status"] = "new"
            row["first_seen"] = now_iso
        merged.append(row)

    # Disappeared: in previous but not in new — resolve unless user had "blocked"
    resolved: List[Dict[str, Any]] = []
    for k, old_entry in prev_by_key.items():
        if k in new_keys:
            continue
        row = dict(old_entry)
        if (row.get("status") or "open") == "blocked":
            # Keep blocked even when no longer in scan
            pass
        else:
            row["status"] = "resolved"
            row["resolved_at"] = now_iso
        resolved.append(row)

    # Keep only the most recent resolved entries
    if len(resolved) > max_resolved:
        resolved = resolved[-max_resolved:]

    merged.extend(resolved)
    return merged
