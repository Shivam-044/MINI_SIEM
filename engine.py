"""
engine.py  ─  SIEM Correlation Engine  (Phase 3)
══════════════════════════════════════════════════════════════════════════════
Queries  data/siem_logs.db  every 10 seconds, runs detection rules against
recent  security_events  rows, and writes fired alerts to a new  alerts
table in the same database.

Built-in rules
──────────────
  RULE-001  Brute Force by Username
            Fires HIGH when ≥ 5 EID-4625 (Failed Logon) events share the
            same username within a rolling 60-second window.

  RULE-002  Brute Force by Source IP   (bonus – same pattern, different key)
            Fires HIGH when ≥ 5 EID-4625 events share the same source_ip
            within 60 seconds.

  RULE-003  Successful Logon After Brute Force  (bonus – correlation rule)
            Fires CRITICAL when a EID-4624 (Success) follows ≥ 3 failures
            for the same username within 120 seconds – a likely credential-
            stuffing hit.

Usage:
    python engine.py                    # run forever, poll every 10 s
    python engine.py --interval 5       # poll every 5 s
    python engine.py --db data/siem_logs.db
    python engine.py --list-alerts      # print stored alerts, then exit
    python engine.py --list-alerts --limit 50
    python engine.py --once             # run rules once, print result, exit
══════════════════════════════════════════════════════════════════════════════
"""

# ─────────────────────────────────────────────────────────────────────────────
# stdlib only – no extra pip installs required
# ─────────────────────────────────────────────────────────────────────────────
import argparse
import logging
import os
import sqlite3
import time
from collections import defaultdict
from datetime    import datetime, timedelta
from pathlib     import Path
from typing      import Dict, List, Optional, Tuple


# ═════════════════════════════════════════════════════════════════════════════
# CONFIG
# ═════════════════════════════════════════════════════════════════════════════

DB_PATH          : str   = os.path.join("data", "siem_logs.db")
POLL_INTERVAL_S  : int   = 10          # seconds between rule evaluations
LOOK_BACK_S      : int   = 120         # how far back to fetch events each cycle
                                        # (wider than any single rule window)

# ─────────────────────────────────────────────────────────────────────────────
# ANSI colours  (Windows 10+ / any ANSI terminal)
# ─────────────────────────────────────────────────────────────────────────────
C: Dict[str, str] = {
    "reset"  : "\033[0m",
    "bold"   : "\033[1m",
    "dim"    : "\033[2m",
    "red"    : "\033[91m",    # HIGH alerts
    "orange" : "\033[38;5;208m",  # MEDIUM alerts
    "yellow" : "\033[93m",    # LOW alerts
    "magenta": "\033[95m",    # CRITICAL alerts
    "green"  : "\033[92m",
    "cyan"   : "\033[96m",
}

SEVERITY_COLOUR: Dict[str, str] = {
    "LOW"      : C["yellow"],
    "MEDIUM"   : C["orange"],
    "HIGH"     : C["red"],
    "CRITICAL" : C["magenta"],
}

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    format  = "%(asctime)s  [%(levelname)s]  %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
    level   = logging.INFO,
)
log = logging.getLogger("engine")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE A  ─  Database Layer
#
# Responsibilities:
#   1. Open  data/siem_logs.db  (created by collector.py).
#   2. Create the  alerts  table on first run if absent.
#   3. Provide read access to  security_events.
#   4. Provide  insert_alert()  to store fired detections.
# ═════════════════════════════════════════════════════════════════════════════

# ── DDL ───────────────────────────────────────────────────────────────────────

_DDL_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER  PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT     NOT NULL,          -- ISO-8601 when the alert fired
    alert_type   TEXT     NOT NULL,          -- rule identifier, e.g. RULE-001
    description  TEXT     NOT NULL,          -- human-readable detail
    severity     TEXT     NOT NULL           -- LOW | MEDIUM | HIGH | CRITICAL
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);
"""

_DDL_ALERT_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_al_timestamp  ON alerts (timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_al_alert_type ON alerts (alert_type);",
    "CREATE INDEX IF NOT EXISTS idx_al_severity   ON alerts (severity);",
)

# Named-parameter INSERT for alerts
_SQL_INSERT_ALERT = """
INSERT INTO alerts (timestamp, alert_type, description, severity)
VALUES             (:timestamp, :alert_type, :description, :severity);
"""

# Query: all failed logons in the last N seconds
_SQL_RECENT_FAILURES = """
SELECT   username, source_ip, workstation_name, timestamp
FROM     security_events
WHERE    status    = 'FAILURE'
  AND    event_id  = 4625
  AND    timestamp >= :since
ORDER BY timestamp ASC;
"""

# Query: all successful logons in the last N seconds
_SQL_RECENT_SUCCESSES = """
SELECT   username, source_ip, timestamp
FROM     security_events
WHERE    status    = 'SUCCESS'
  AND    event_id  = 4624
  AND    timestamp >= :since
ORDER BY timestamp ASC;
"""

# Deduplication guard: was an identical alert already fired in the last N seconds?
_SQL_RECENT_ALERT = """
SELECT COUNT(*) FROM alerts
WHERE  alert_type = :alert_type
  AND  description = :description
  AND  timestamp  >= :since;
"""


def _ensure_db_exists(db_path: str) -> None:
    """Raise a clear error if the database file is missing."""
    if not Path(db_path).exists():
        raise FileNotFoundError(
            f"Database not found: {db_path}\n"
            "Make sure collector.py has been run at least once to create it."
        )


class EngineDatabase:
    """
    Read/write access to  siem_logs.db  for the correlation engine.
    Adds the  alerts  table if it doesn't already exist.

    Usage (context manager):
        with EngineDatabase("data/siem_logs.db") as db:
            rows = db.fetch_recent_failures(window_seconds=120)
            db.insert_alert(alert_dict)
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def connect(self) -> None:
        _ensure_db_exists(self.db_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL;")
        self._conn.execute("PRAGMA synchronous  = NORMAL;")
        self._bootstrap_alerts()
        log.info("Engine connected to: %s", os.path.abspath(self.db_path))

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "EngineDatabase":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ── Bootstrap ─────────────────────────────────────────────────────────────

    def _bootstrap_alerts(self) -> None:
        """Create the alerts table and its indexes if they don't exist."""
        cur = self._conn.cursor()
        cur.executescript(_DDL_ALERTS_TABLE)
        for ddl in _DDL_ALERT_INDEXES:
            cur.execute(ddl)
        self._conn.commit()
        log.debug("alerts table verified.")

    # ── Read ──────────────────────────────────────────────────────────────────

    def fetch_recent_failures(self, window_seconds: int) -> List[sqlite3.Row]:
        """
        Return all EID-4625 rows with timestamps in the last `window_seconds`.
        Used by every failure-based detection rule.
        """
        since = (datetime.now() - timedelta(seconds=window_seconds)
                 ).strftime("%Y-%m-%dT%H:%M:%S")
        return self._conn.execute(_SQL_RECENT_FAILURES, {"since": since}).fetchall()

    def fetch_recent_successes(self, window_seconds: int) -> List[sqlite3.Row]:
        """Return all EID-4624 rows in the last `window_seconds`."""
        since = (datetime.now() - timedelta(seconds=window_seconds)
                 ).strftime("%Y-%m-%dT%H:%M:%S")
        return self._conn.execute(_SQL_RECENT_SUCCESSES, {"since": since}).fetchall()

    def fetch_alerts(self, limit: int = 25) -> List[sqlite3.Row]:
        """Return the most-recent `limit` alerts (newest first)."""
        return self._conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    # ── Deduplication ─────────────────────────────────────────────────────────

    def alert_recently_fired(
        self,
        alert_type: str,
        description: str,
        cooldown_seconds: int = 120,
    ) -> bool:
        """
        Return True if an identical alert (same type + description) was already
        stored within the last `cooldown_seconds`.

        This prevents the engine from spamming the same alert every 10 seconds
        for an ongoing brute-force attack.
        """
        since = (datetime.now() - timedelta(seconds=cooldown_seconds)
                 ).strftime("%Y-%m-%dT%H:%M:%S")
        count = self._conn.execute(_SQL_RECENT_ALERT, {
            "alert_type"  : alert_type,
            "description" : description,
            "since"       : since,
        }).fetchone()[0]
        return count > 0

    # ── Write ─────────────────────────────────────────────────────────────────

    def insert_alert(self, alert: dict) -> int:
        """
        Persist one alert dict to the  alerts  table.
        Required keys: alert_type, description, severity.
        timestamp is auto-set to now if absent.

        Returns the new row's auto-incremented id.
        """
        if "timestamp" not in alert:
            alert = {**alert, "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}

        cur = self._conn.execute(_SQL_INSERT_ALERT, alert)
        self._conn.commit()
        return cur.lastrowid


# ═════════════════════════════════════════════════════════════════════════════
# MODULE B  ─  Detection Rules
#
# Each rule is a plain function with the signature:
#
#   def rule_XXXX(db: EngineDatabase) -> List[dict]:
#
# It returns a (possibly empty) list of alert dicts ready for insert_alert().
# Adding a new rule = writing one new function + registering it in RULES.
# ═════════════════════════════════════════════════════════════════════════════

# ── Shared constants ──────────────────────────────────────────────────────────

BRUTE_FORCE_WINDOW_S   : int = 60     # sliding window length (seconds)
BRUTE_FORCE_THRESHOLD  : int = 5      # failures needed to trigger
ALERT_COOLDOWN_S       : int = 120    # suppress duplicate alerts for 2 min

BF_IP_WINDOW_S         : int = 60
BF_IP_THRESHOLD        : int = 5

SUCCESS_AFTER_BF_WINDOW  : int = 120
SUCCESS_AFTER_BF_FAILURES: int = 3    # fewer failures needed for this rule


# ─────────────────────────────────────────────────────────────────────────────
# RULE-001  Brute Force Detection by Username
# ─────────────────────────────────────────────────────────────────────────────

def rule_001_brute_force_username(db: EngineDatabase) -> List[dict]:
    """
    Fire HIGH alert when the same *username* has ≥ BRUTE_FORCE_THRESHOLD
    failed logons (EID-4625) within BRUTE_FORCE_WINDOW_S seconds.

    Algorithm
    ─────────
    1. Fetch all failures in the last BRUTE_FORCE_WINDOW_S seconds.
    2. Group by username using a defaultdict counter.
    3. For each username that meets the threshold, build an alert dict.
    4. Check the deduplication guard before appending.
    """
    alerts    : List[dict] = []
    failures  = db.fetch_recent_failures(BRUTE_FORCE_WINDOW_S)

    # Group timestamps by username
    by_user: Dict[str, List[str]] = defaultdict(list)
    for row in failures:
        by_user[row["username"]].append(row["timestamp"])

    for username, timestamps in by_user.items():
        if username in ("-", "", "unknown"):
            continue                    # skip placeholder / anonymous entries

        count = len(timestamps)
        if count < BRUTE_FORCE_THRESHOLD:
            continue

        description = (
            f"Brute force detected against username '{username}': "
            f"{count} failed logon(s) in {BRUTE_FORCE_WINDOW_S}s "
            f"(threshold: {BRUTE_FORCE_THRESHOLD})"
        )

        # Deduplication: don't re-fire if we already stored this same alert recently
        if db.alert_recently_fired("RULE-001", description, ALERT_COOLDOWN_S):
            continue

        alerts.append({
            "alert_type"  : "RULE-001",
            "description" : description,
            "severity"    : "HIGH",
        })

    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# RULE-002  Brute Force Detection by Source IP  (bonus rule)
# ─────────────────────────────────────────────────────────────────────────────

def rule_002_brute_force_ip(db: EngineDatabase) -> List[dict]:
    """
    Fire HIGH alert when the same *source IP* has ≥ BF_IP_THRESHOLD
    failed logons within BF_IP_WINDOW_S seconds.

    This complements RULE-001: an attacker using credential-stuffing may
    target many different usernames from one IP, which RULE-001 would miss.
    """
    alerts   : List[dict] = []
    failures = db.fetch_recent_failures(BF_IP_WINDOW_S)

    by_ip: Dict[str, List[str]] = defaultdict(list)
    for row in failures:
        by_ip[row["source_ip"]].append(row["timestamp"])

    for source_ip, timestamps in by_ip.items():
        if source_ip in ("-", "", "unknown", "localhost"):
            continue

        count = len(timestamps)
        if count < BF_IP_THRESHOLD:
            continue

        description = (
            f"Brute force from IP '{source_ip}': "
            f"{count} failed logon(s) in {BF_IP_WINDOW_S}s "
            f"(threshold: {BF_IP_THRESHOLD})"
        )

        if db.alert_recently_fired("RULE-002", description, ALERT_COOLDOWN_S):
            continue

        alerts.append({
            "alert_type"  : "RULE-002",
            "description" : description,
            "severity"    : "HIGH",
        })

    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# RULE-003  Successful Logon After Brute Force  (bonus – correlation rule)
# ─────────────────────────────────────────────────────────────────────────────

def rule_003_success_after_brute_force(db: EngineDatabase) -> List[dict]:
    """
    Fire CRITICAL when a username that has ≥ SUCCESS_AFTER_BF_FAILURES recent
    failures also records a successful logon within SUCCESS_AFTER_BF_WINDOW
    seconds.

    This is the "brute force that worked" signature – the most dangerous
    finding a SIEM can surface.
    """
    alerts   : List[dict] = []
    failures  = db.fetch_recent_failures(SUCCESS_AFTER_BF_WINDOW)
    successes = db.fetch_recent_successes(SUCCESS_AFTER_BF_WINDOW)

    # Count failures per username
    failure_counts: Dict[str, int] = defaultdict(int)
    for row in failures:
        failure_counts[row["username"]] += 1

    # Build set of usernames that recently succeeded
    success_users = {row["username"] for row in successes}

    for username, fail_count in failure_counts.items():
        if username in ("-", "", "unknown"):
            continue
        if fail_count < SUCCESS_AFTER_BF_FAILURES:
            continue
        if username not in success_users:
            continue

        description = (
            f"POSSIBLE COMPROMISE: '{username}' had {fail_count} failed "
            f"logon(s) followed by a SUCCESSFUL logon within "
            f"{SUCCESS_AFTER_BF_WINDOW}s — credential stuffing likely."
        )

        if db.alert_recently_fired("RULE-003", description, ALERT_COOLDOWN_S):
            continue

        alerts.append({
            "alert_type"  : "RULE-003",
            "description" : description,
            "severity"    : "CRITICAL",
        })

    return alerts


# ── Rule registry ─────────────────────────────────────────────────────────────
# Add a new rule: write the function above, then append it here.
# The engine loop calls every entry in this list on every cycle.

RULES = [
    rule_001_brute_force_username,
    rule_002_brute_force_ip,
    rule_003_success_after_brute_force,
]


# ═════════════════════════════════════════════════════════════════════════════
# MODULE C  ─  Alert Output  (console + storage)
# ═════════════════════════════════════════════════════════════════════════════

# Width of the alert banner line
_BANNER_WIDTH = 72


def _severity_colour(severity: str) -> str:
    return SEVERITY_COLOUR.get(severity.upper(), C["yellow"])


def print_alert(alert: dict, row_id: Optional[int] = None) -> None:
    """
    Print a fired alert to the console with full ANSI red/colour formatting.

    Layout:
    ╔══════════════════════════════════  ALERT  ══════════════════════════╗
    ║  [2026-05-07T14:23:01]  RULE-001  ·  HIGH                          ║
    ║  Brute force detected against username 'admin': 7 failed …         ║
    ╚═════════════════════════════════════════════════════════════════════╝
    """
    colour    = _severity_colour(alert.get("severity", "HIGH"))
    b, r      = C["bold"], C["reset"]
    ts        = alert.get("timestamp", datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))
    rid_str   = f"  #{row_id}" if row_id else ""

    top    = f"╔{'═' * (_BANNER_WIDTH - 2)}╗"
    mid    = f"╠{'═' * (_BANNER_WIDTH - 2)}╣"
    bot    = f"╚{'═' * (_BANNER_WIDTH - 2)}╝"

    header = (
        f"  [{ts}]  {alert['alert_type']}  ·  "
        f"{alert['severity']}{rid_str}"
    )
    # Word-wrap description at banner width
    desc      = alert["description"]
    desc_lines = []
    while len(desc) > _BANNER_WIDTH - 4:
        split = desc[: _BANNER_WIDTH - 4].rfind(" ")
        split = split if split > 0 else _BANNER_WIDTH - 4
        desc_lines.append("  " + desc[:split])
        desc = desc[split:].lstrip()
    desc_lines.append("  " + desc)

    print(f"\n{colour}{b}{top}{r}")
    print(f"{colour}{b}║  ⚠  SIEM ALERT{' ' * (_BANNER_WIDTH - 16)}║{r}")
    print(f"{colour}{b}{mid}{r}")
    print(f"{colour}{b}║{header:<{_BANNER_WIDTH - 2}}║{r}")
    for dl in desc_lines:
        print(f"{colour}║{dl:<{_BANNER_WIDTH - 2}}║{r}")
    print(f"{colour}{b}{bot}{r}\n")


def print_alert_table(rows: List[sqlite3.Row], title: str = "Stored Alerts") -> None:
    """Render stored alerts as a compact ASCII table (--list-alerts mode)."""
    if not rows:
        print("\n  (no alerts stored yet)\n")
        return

    cols   = ["id", "timestamp", "alert_type", "severity", "description"]
    widths = {c: len(c) for c in cols}
    data   = [dict(r) for r in rows]

    # cap description display width
    for row in data:
        row["description"] = row["description"][:60] + ("…" if len(row["description"]) > 60 else "")

    for row in data:
        for c in cols:
            widths[c] = max(widths[c], len(str(row.get(c, ""))))

    sep = "+" + "+".join("-" * (widths[c] + 2) for c in cols) + "+"
    hdr = "|" + "|".join(f" {c.upper():<{widths[c]}} " for c in cols) + "|"

    print(f"\n  {C['bold']}{title}{C['reset']}")
    print(sep); print(hdr); print(sep)

    for row in data:
        clr  = _severity_colour(row.get("severity", ""))
        line = "|" + "|".join(
            f" {clr if c == 'severity' else ''}"
            f"{str(row.get(c, '')):<{widths[c]}}"
            f"{C['reset'] if c == 'severity' else ''} "
            for c in cols
        ) + "|"
        print(line)

    print(sep)
    print(f"  {len(data)} alert(s)\n")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE D  ─  Engine Loop
# ═════════════════════════════════════════════════════════════════════════════

def run_cycle(db: EngineDatabase) -> int:
    """
    Execute every registered rule once.
    Persist and print each fired alert.
    Returns the number of new alerts generated in this cycle.
    """
    fired = 0
    for rule_fn in RULES:
        try:
            alerts = rule_fn(db)
        except Exception as exc:
            log.error("Rule %s raised an exception: %s", rule_fn.__name__, exc)
            continue

        for alert in alerts:
            try:
                row_id = db.insert_alert(alert)
                print_alert(alert, row_id)
                fired += 1
                log.info(
                    "Alert stored  id=%-5s  type=%s  severity=%s",
                    row_id, alert["alert_type"], alert["severity"]
                )
            except sqlite3.Error as exc:
                log.error("Failed to store alert: %s  |  alert=%s", exc, alert)

    return fired


def run_engine(db_path: str, interval: int = POLL_INTERVAL_S) -> None:
    """
    Main engine loop.  Runs run_cycle() every `interval` seconds until
    interrupted with Ctrl+C.
    """
    with EngineDatabase(db_path) as db:
        log.info(
            "Correlation engine started  |  DB: %s  |  interval: %ds  |  "
            "rules: %d  |  Ctrl+C to stop.",
            os.path.abspath(db_path), interval, len(RULES)
        )
        _print_startup_banner(interval)

        while True:
            cycle_start = time.monotonic()
            log.debug("Running %d rule(s)…", len(RULES))

            fired = run_cycle(db)
            if fired == 0:
                log.debug("Cycle complete — no new alerts.")
            else:
                log.info("Cycle complete — %d new alert(s) fired.", fired)

            # Sleep for the remainder of the interval
            elapsed = time.monotonic() - cycle_start
            sleep_s = max(0.0, interval - elapsed)
            time.sleep(sleep_s)


# ═════════════════════════════════════════════════════════════════════════════
# MODULE E  ─  UI helpers
# ═════════════════════════════════════════════════════════════════════════════

def _print_startup_banner(interval: int) -> None:
    b, r, cy = C["bold"], C["reset"], C["cyan"]
    rule_lines = "\n".join(
        f"    {cy}[{fn.__name__}]{r}  {fn.__doc__.strip().splitlines()[0]}"
        for fn in RULES
    )
    print(f"""
{b}{'═'*60}
  SIEM Correlation Engine  ─  Phase 3
{'═'*60}{r}
  Database  : {C['dim']}{os.path.abspath(DB_PATH)}{r}
  Poll every: {b}{interval}s{r}
  Rules     : {b}{len(RULES)}{r}
{rule_lines}
{b}{'─'*60}{r}
""")


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description = "SIEM Correlation Engine  (Phase 3)",
        formatter_class = argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--db",       default=DB_PATH,
                   help=f"Path to SQLite database  (default: {DB_PATH})")
    p.add_argument("--interval", type=int, default=POLL_INTERVAL_S,
                   help=f"Poll interval in seconds  (default: {POLL_INTERVAL_S})")
    p.add_argument("--once",     action="store_true",
                   help="Run all rules once and exit  (useful for testing)")
    p.add_argument("--list-alerts", action="store_true",
                   help="Print stored alerts from the DB, then exit")
    p.add_argument("--limit", type=int, default=25,
                   help="Rows to show with --list-alerts  (default: 25)")
    return p


def main() -> None:
    args = _build_parser().parse_args()

    # ── Read-only / one-shot modes ────────────────────────────────────────────
    if args.list_alerts:
        with EngineDatabase(args.db) as db:
            rows = db.fetch_alerts(args.limit)
            print_alert_table(rows, title=f"Last {args.limit} Alerts  –  {args.db}")
        return

    if args.once:
        with EngineDatabase(args.db) as db:
            _print_startup_banner(args.interval)
            fired = run_cycle(db)
            print(f"\n  One-shot run complete.  {fired} alert(s) fired.\n")
        return

    # ── Continuous engine loop ────────────────────────────────────────────────
    try:
        run_engine(args.db, args.interval)
    except FileNotFoundError as exc:
        log.error("%s", exc)
    except KeyboardInterrupt:
        log.info("Engine stopped.")


if __name__ == "__main__":
    main()