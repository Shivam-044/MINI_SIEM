"""
collector.py  ─  SIEM Phase 2
══════════════════════════════════════════════════════════════════════════════
Reads Windows Security Event IDs 4624 / 4625 in real-time, extracts precise
network fields (Source Network Address + Workstation Name), and persists
every event to  data/siem_logs.db  via a clean SQLite layer.

Requirements:
    pip install pywin32          ← only external dependency (sqlite3 is stdlib)

Run (must be Administrator):
    python collector.py                    # live tail
    python collector.py --poll 1           # 1-second poll interval
    python collector.py --query            # inspect DB, then exit
    python collector.py --query --limit 50
    python collector.py --stats            # threat summary, then exit
    python collector.py --db other.db      # custom DB path
══════════════════════════════════════════════════════════════════════════════
"""

# ─────────────────────────────────────────────────────────────────────────────
# stdlib  (zero extra installs)
# ─────────────────────────────────────────────────────────────────────────────
import argparse
import logging
import os
import sqlite3
import time
from datetime import datetime
from pathlib  import Path
from typing   import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Windows-only (pywin32)
# ─────────────────────────────────────────────────────────────────────────────
try:
    import win32evtlog
    import winerror
    import pywintypes
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False          # lets the module load on non-Windows too

# ═════════════════════════════════════════════════════════════════════════════
# CONFIG
# ═════════════════════════════════════════════════════════════════════════════

# ── Phase 2 requirement: DB lives inside a  data/  sub-directory ─────────────
DB_DIR  : str = "data"
DB_NAME : str = "siem_logs.db"
DB_PATH : str = os.path.join(DB_DIR, DB_NAME)   # "data/siem_logs.db"

TARGET_EVENT_IDS: set = {4624, 4625}

# Human-readable logon types (Microsoft documentation)
LOGON_TYPE_MAP: dict = {
    "2":  "Interactive",
    "3":  "Network",
    "4":  "Batch",
    "5":  "Service",
    "7":  "Unlock",
    "8":  "NetworkCleartext",
    "9":  "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}

# ANSI colour helpers (terminal output only)
C = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
    "red":    "\033[91m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
}

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    format  = "%(asctime)s  [%(levelname)s]  %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
    level   = logging.INFO,
)
log = logging.getLogger("collector")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE A  ─  Event Parser
#
# Goal (Phase 2): precisely extract
#   • Source Network Address  (IpAddress field)
#   • Workstation Name        (WorkstationName field)
#
# Both fields use fixed StringInserts indices that differ per Event ID.
# The full Microsoft schema is documented inline so the indices are
# self-explanatory and easy to extend.
# ═════════════════════════════════════════════════════════════════════════════

# ── StringInserts index maps ──────────────────────────────────────────────────
#
# Event 4624 – Successful Logon
# Index  Field name (as shown in Event Viewer XML)
# ─────  ────────────────────────────────────────
#   0    SubjectUserSid
#   1    SubjectUserName
#   2    SubjectDomainName
#   3    SubjectLogonId
#   4    TargetUserSid
#   5    TargetUserName          ← username we care about
#   6    TargetDomainName        ← domain   we care about
#   7    TargetLogonId
#   8    LogonType               ← logon type
#   9    LogonProcessName
#  10    AuthenticationPackageName
#  11    WorkstationName         ← Phase 2: workstation
#  12    LogonGuid
#  13    TransmittedServices
#  14    LmPackageName
#  15    KeyLength
#  16    ProcessId
#  17    ProcessName
#  18    IpAddress               ← Phase 2: source IP
#  19    IpPort
#
# Event 4625 – Failed Logon
# Index  Field name
# ─────  ──────────────────────────────────────────
#   0    SubjectUserSid
#   1    SubjectUserName
#   2    SubjectDomainName
#   3    SubjectLogonId
#   4    TargetUserSid
#   5    TargetUserName          ← username
#   6    TargetDomainName        ← domain
#   7    Status
#   8    FailureReason
#   9    SubStatus
#  10    LogonType               ← logon type
#  11    LogonProcessName
#  12    AuthenticationPackageName
#  13    WorkstationName         ← Phase 2: workstation
#  14    TransmittedServices
#  15    LmPackageName
#  16    KeyLength
#  17    ProcessId
#  18    ProcessName
#  19    IpAddress               ← Phase 2: source IP
#  20    IpPort

# Slot definitions: (event_id → field_name → insert_index)
_IDX: dict = {
    4624: {
        "username"         : 5,
        "domain"           : 6,
        "logon_type"       : 8,
        "workstation_name" : 11,   # ← Phase 2
        "source_ip"        : 18,   # ← Phase 2
        "source_port"      : 19,
    },
    4625: {
        "username"         : 5,
        "domain"           : 6,
        "failure_reason"   : 8,
        "logon_type"       : 10,
        "workstation_name" : 13,   # ← Phase 2
        "source_ip"        : 19,   # ← Phase 2
        "source_port"      : 20,
    },
}


def _get(inserts: list, idx: int, fallback: str = "-") -> str:
    """
    Bounds-safe accessor for StringInserts.
    Returns the stripped string at `idx`, or `fallback` if absent / blank.
    """
    try:
        val = inserts[idx].strip()
        return val if val else fallback
    except (IndexError, AttributeError, TypeError):
        return fallback


def _clean_ip(raw: str) -> str:
    """
    Normalise Windows IP placeholder values to human-readable strings.

    Windows may report:
        "-"         → no IP in this logon type (e.g. interactive console)
        "::"        → IPv6 unspecified
        "::1"       → IPv6 loopback
        "127.0.0.1" → IPv4 loopback
    """
    loopback = {"", "-", "::", "::1", "127.0.0.1"}
    return "localhost" if raw in loopback else raw


def _clean_workstation(raw: str) -> str:
    """
    Normalise workstation name placeholders.
    Windows may emit "-" for interactive/service logons.
    """
    return raw if raw not in ("", "-") else "local"


def parse_event(event) -> Optional[dict]:
    """
    Convert a raw pywin32 EVENTLOGRECORD into a clean, typed Python dict.

    Returned schema (consistent across both Event IDs):
    ┌─────────────────────┬──────────────────────────────────────────────┐
    │ Key                 │ Value                                        │
    ├─────────────────────┼──────────────────────────────────────────────┤
    │ timestamp           │ "2026-05-07T14:23:01"  (local time ISO-8601) │
    │ event_id            │ 4624 | 4625                                  │
    │ status              │ "SUCCESS" | "FAILURE"                        │
    │ username            │ TargetUserName                               │
    │ domain              │ TargetDomainName                             │
    │ source_ip           │ IpAddress  (normalised)         ← Phase 2   │
    │ workstation_name    │ WorkstationName (normalised)    ← Phase 2   │
    │ source_port         │ IpPort                                       │
    │ logon_type          │ Human-readable string                        │
    │ computer            │ Generating machine hostname                  │
    │ failure_reason      │ Reason string for 4625, None for 4624        │
    └─────────────────────┴──────────────────────────────────────────────┘

    Returns None for events outside TARGET_EVENT_IDS.
    """
    event_id = event.EventID & 0xFFFF          # strip the qualifier high bits
    if event_id not in TARGET_EVENT_IDS:
        return None

    inserts = event.StringInserts or []
    idx     = _IDX[event_id]

    # ── Timestamp ────────────────────────────────────────────────────────────
    try:
        timestamp = event.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S")
    except Exception:
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    # ── Phase 2 : precise field extraction ───────────────────────────────────
    source_ip         = _clean_ip(        _get(inserts, idx["source_ip"])         )
    workstation_name  = _clean_workstation(_get(inserts, idx["workstation_name"]) )

    # ── Remaining fields ─────────────────────────────────────────────────────
    username     = _get(inserts, idx["username"])
    domain       = _get(inserts, idx["domain"])
    source_port  = _get(inserts, idx["source_port"])
    logon_raw    = _get(inserts, idx["logon_type"])
    logon_type   = LOGON_TYPE_MAP.get(logon_raw, f"Type-{logon_raw}")

    if event_id == 4624:
        status         = "SUCCESS"
        failure_reason = None
    else:
        status         = "FAILURE"
        failure_reason = _get(inserts, idx["failure_reason"])

    return {
        "timestamp"       : timestamp,
        "event_id"        : event_id,
        "status"          : status,
        "username"        : username,
        "domain"          : domain,
        "source_ip"       : source_ip,           # ← Phase 2
        "workstation_name": workstation_name,     # ← Phase 2
        "source_port"     : source_port,
        "logon_type"      : logon_type,
        "computer"        : getattr(event, "ComputerName", "-"),
        "failure_reason"  : failure_reason,
    }


# ═════════════════════════════════════════════════════════════════════════════
# MODULE B  ─  Database Layer
#
# Phase 2 requirements:
#   1.  Auto-create  data/  directory if it does not exist.
#   2.  Create  siem_logs.db  and the  security_events  table on first run.
#   3.  Expose  insert_event(ev)  for use in the main collection loop.
# ═════════════════════════════════════════════════════════════════════════════

# ── DDL ───────────────────────────────────────────────────────────────────────

_DDL_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS security_events (
    -- Required columns (Phase 2 spec)
    id                INTEGER  PRIMARY KEY AUTOINCREMENT,
    timestamp         TEXT     NOT NULL,
    event_id          INTEGER  NOT NULL,
    username          TEXT     NOT NULL DEFAULT '-',
    source_ip         TEXT     NOT NULL DEFAULT '-',
    status            TEXT     NOT NULL CHECK (status IN ('SUCCESS', 'FAILURE')),

    -- Extended columns (same row – avoids joins)
    workstation_name  TEXT     DEFAULT '-',
    domain            TEXT     DEFAULT '-',
    source_port       TEXT     DEFAULT '-',
    logon_type        TEXT,
    computer          TEXT,
    failure_reason    TEXT     -- NULL for 4624 rows
);
"""

# Indexes that matter for the queries you'll run most:
#   - time-range slices      → idx_timestamp
#   - IP-based threat hunting → idx_source_ip
#   - failure dashboards     → idx_status
_DDL_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_se_timestamp  ON security_events (timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_se_source_ip  ON security_events (source_ip);",
    "CREATE INDEX IF NOT EXISTS idx_se_status     ON security_events (status);",
    "CREATE INDEX IF NOT EXISTS idx_se_username   ON security_events (username);",
)

# Named-parameter INSERT  – dict keys match column names exactly
_SQL_INSERT = """
INSERT INTO security_events (
    timestamp, event_id, username, source_ip, status,
    workstation_name, domain, source_port, logon_type,
    computer, failure_reason
) VALUES (
    :timestamp, :event_id, :username, :source_ip, :status,
    :workstation_name, :domain, :source_port, :logon_type,
    :computer, :failure_reason
);
"""


def _ensure_data_dir(db_path: str) -> None:
    """
    Phase 2 – safely create the  data/  directory (or any parent dirs)
    before SQLite tries to open a file inside it.

    Uses Path.mkdir(parents=True, exist_ok=True) so:
      • No exception if the directory already exists.
      • Handles nested paths like  data/prod/siem_logs.db  too.
    """
    parent = Path(db_path).parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
        log.info("Created directory: %s", parent)


class EventDatabase:
    """
    Thin, context-manager-aware SQLite wrapper.

    Usage:
        with EventDatabase() as db:
            db.insert_event(ev)

    All SQL lives here.  Nothing outside this class touches sqlite3.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path : str                       = db_path
        self._conn   : Optional[sqlite3.Connection] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def connect(self) -> None:
        """
        Open (or create) the database, apply performance PRAGMAs,
        and bootstrap the schema.  Safe to call multiple times.
        """
        _ensure_data_dir(self.db_path)           # Phase 2: mkdir -p

        self._conn = sqlite3.connect(
            self.db_path,
            check_same_thread = False,           # single-writer, safe here
        )
        self._conn.row_factory = sqlite3.Row     # rows act like dicts

        # WAL mode: readers never block writers; writers never block readers
        self._conn.execute("PRAGMA journal_mode = WAL;")
        # NORMAL sync: ~3× faster than FULL, still survives OS crashes
        self._conn.execute("PRAGMA synchronous  = NORMAL;")

        self._bootstrap()
        log.info("Database ready → %s", os.path.abspath(self.db_path))

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "EventDatabase":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ── Schema bootstrap ──────────────────────────────────────────────────────

    def _bootstrap(self) -> None:
        """Create table and indexes if they do not already exist."""
        cur = self._conn.cursor()
        cur.executescript(_DDL_CREATE_TABLE)
        for ddl in _DDL_INDEXES:
            cur.execute(ddl)
        self._conn.commit()
        log.debug("Schema verified.")

    # ── Write ─────────────────────────────────────────────────────────────────

    def insert_event(self, ev: dict) -> int:
        """
        Phase 2 – persist one normalised event dict to security_events.

        Parameters
        ----------
        ev : dict
            Output of parse_event().  Keys must match the named params
            in _SQL_INSERT; extra keys are ignored by sqlite3.

        Returns
        -------
        int
            The auto-incremented  id  of the newly inserted row.

        Raises
        ------
        sqlite3.Error
            Re-raised after logging so the caller can decide to skip
            or abort.  The connection remains usable after the error.
        """
        try:
            cur = self._conn.execute(_SQL_INSERT, ev)
            self._conn.commit()
            return cur.lastrowid
        except sqlite3.Error as exc:
            log.error("insert_event failed: %s  |  event=%s", exc, ev)
            raise

    def insert_batch(self, events: list) -> int:
        """
        Bulk-insert a list of event dicts in a single transaction.
        Returns the number of rows inserted.
        """
        self._conn.executemany(_SQL_INSERT, events)
        self._conn.commit()
        return len(events)

    # ── Read helpers ──────────────────────────────────────────────────────────

    def fetch_recent(self, limit: int = 25) -> list:
        """Return the `limit` most-recent rows (newest first)."""
        return self._conn.execute(
            "SELECT * FROM security_events ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()

    def fetch_by_ip(self, ip: str, limit: int = 100) -> list:
        """Return all events from a specific source IP."""
        return self._conn.execute(
            "SELECT * FROM security_events "
            "WHERE source_ip = ? ORDER BY id DESC LIMIT ?",
            (ip, limit)
        ).fetchall()

    def fetch_stats(self) -> dict:
        """Aggregate counters for the threat-summary dashboard."""
        cur = self._conn.cursor()

        total   = cur.execute("SELECT COUNT(*) FROM security_events"          ).fetchone()[0]
        success = cur.execute("SELECT COUNT(*) FROM security_events WHERE status='SUCCESS'").fetchone()[0]
        failure = cur.execute("SELECT COUNT(*) FROM security_events WHERE status='FAILURE'").fetchone()[0]

        top_ips = cur.execute("""
            SELECT source_ip, COUNT(*) AS cnt
            FROM   security_events
            WHERE  status = 'FAILURE'
              AND  source_ip NOT IN ('localhost', '-', 'unknown')
            GROUP  BY source_ip
            ORDER  BY cnt DESC
            LIMIT  10
        """).fetchall()

        top_users = cur.execute("""
            SELECT username, COUNT(*) AS cnt
            FROM   security_events
            WHERE  status = 'FAILURE'
              AND  username != '-'
            GROUP  BY username
            ORDER  BY cnt DESC
            LIMIT  10
        """).fetchall()

        top_workstations = cur.execute("""
            SELECT workstation_name, COUNT(*) AS cnt
            FROM   security_events
            WHERE  status = 'FAILURE'
              AND  workstation_name NOT IN ('local', '-')
            GROUP  BY workstation_name
            ORDER  BY cnt DESC
            LIMIT  5
        """).fetchall()

        return {
            "total"            : total,
            "success_count"    : success,
            "failure_count"    : failure,
            "top_failed_ips"   : [(r["source_ip"],         r["cnt"]) for r in top_ips],
            "top_failed_users" : [(r["username"],           r["cnt"]) for r in top_users],
            "top_workstations" : [(r["workstation_name"],   r["cnt"]) for r in top_workstations],
        }


# ═════════════════════════════════════════════════════════════════════════════
# MODULE C  ─  Event Log Tail  (Windows)
# ═════════════════════════════════════════════════════════════════════════════

class EventLogTailer:
    """
    Tails the Windows Security event log using a RecordNumber cursor.
    Skips all pre-existing records on first open (live events only).
    """

    LOG_NAME = "Security"

    def __init__(self, poll_interval: float = 2.0):
        self.poll_interval  = poll_interval
        self._handle        = None
        self._last_record   = 0

    @property
    def _seek_flags(self) -> int:
        return (win32evtlog.EVENTLOG_FORWARDS_READ |
                win32evtlog.EVENTLOG_SEEK_READ)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def _open(self) -> None:
        self._handle = win32evtlog.OpenEventLog(None, self.LOG_NAME)
        total  = win32evtlog.GetNumberOfEventLogRecords(self._handle)
        oldest = win32evtlog.GetOldestEventLogRecord(self._handle)
        # Position cursor at the very last existing record
        self._last_record = oldest + total - 1
        log.info(
            "Opened '%s' event log  |  watching from record #%d onward.",
            self.LOG_NAME, self._last_record + 1
        )

    def _close(self) -> None:
        if self._handle:
            try:
                win32evtlog.CloseEventLog(self._handle)
            except Exception:
                pass
            self._handle = None

    # ── Generator ─────────────────────────────────────────────────────────────

    def tail(self):
        """
        Infinite generator – yields parsed event dicts as they arrive.
        Stops cleanly on KeyboardInterrupt.
        """
        self._open()
        try:
            while True:
                try:
                    raw_events = win32evtlog.ReadEventLog(
                        self._handle,
                        self._seek_flags,
                        self._last_record + 1,
                    )
                except pywintypes.error as exc:
                    # No new records yet
                    if exc.args[0] in (winerror.ERROR_INVALID_PARAMETER,
                                       winerror.ERROR_HANDLE_EOF):
                        time.sleep(self.poll_interval)
                        continue
                    log.error("ReadEventLog error: %s", exc)
                    time.sleep(self.poll_interval)
                    continue

                for raw in raw_events:
                    self._last_record = raw.RecordNumber
                    ev = parse_event(raw)
                    if ev:
                        yield ev

                time.sleep(self.poll_interval)

        except KeyboardInterrupt:
            log.info("Collector stopped by user.")
        finally:
            self._close()


# ═════════════════════════════════════════════════════════════════════════════
# MODULE D  ─  Console Output
# ═════════════════════════════════════════════════════════════════════════════

def _fmt_live(ev: dict, row_id: Optional[int] = None) -> str:
    """Colour-coded single-line summary for live monitoring."""
    colour = C["green"] if ev["status"] == "SUCCESS" else C["red"]
    badge  = f"{colour}{C['bold']}{ev['status']:^9}{C['reset']}"
    rid    = f"{C['dim']}#{row_id:<5}{C['reset']}" if row_id else ""

    parts = [
        rid,
        f"[{ev['timestamp']}]",
        badge,
        f"EID={ev['event_id']}",
        f"user={ev['domain']}\\{ev['username']}",
        f"ip={ev['source_ip']}",              # Phase 2 field
        f"ws={ev['workstation_name']}",       # Phase 2 field
        f"logon={ev['logon_type']}",
    ]
    if ev.get("failure_reason"):
        parts.append(f"reason={ev['failure_reason']}")

    return "  ".join(p for p in parts if p)


def _print_table(rows: list, title: str = "Events") -> None:
    """Pretty ASCII table for --query output."""
    if not rows:
        print("  (no records)\n")
        return

    cols   = ["id", "timestamp", "status", "username",
              "source_ip", "workstation_name", "event_id"]
    widths = {c: len(c) for c in cols}
    data   = [dict(r) for r in rows]

    for row in data:
        for c in cols:
            widths[c] = max(widths[c], len(str(row.get(c, ""))))

    sep = "+" + "+".join("-" * (w + 2) for w in widths.values()) + "+"
    hdr = "|" + "|".join(f" {c.upper():<{widths[c]}} " for c in cols) + "|"

    print(f"\n  {C['bold']}{title}{C['reset']}")
    print(sep); print(hdr); print(sep)

    for row in data:
        clr  = C["green"] if row.get("status") == "SUCCESS" else C["red"]
        line = "|" + "|".join(
            f" {clr if c == 'status' else ''}"
            f"{str(row.get(c, '')):<{widths[c]}}"
            f"{C['reset'] if c == 'status' else ''} "
            for c in cols
        ) + "|"
        print(line)

    print(sep)
    print(f"  {len(data)} row(s)\n")


def _print_stats(stats: dict) -> None:
    """Threat-summary dashboard."""
    b, r = C["bold"], C["reset"]
    y, red, g = C["yellow"], C["red"], C["green"]

    print(f"\n{b}{'═'*56}")
    print("  SIEM  –  Threat Summary")
    print(f"{'═'*56}{r}")
    print(f"  Total events       : {b}{stats['total']}{r}")
    print(f"  Successful logons  : {g}{stats['success_count']}{r}")
    print(f"  Failed logons      : {red}{stats['failure_count']}{r}")

    sections = [
        ("Top attacker IPs (failures)",      "top_failed_ips",    y),
        ("Top targeted usernames (failures)", "top_failed_users",  red),
        ("Top source workstations (failures)","top_workstations",  C["cyan"]),
    ]
    for title, key, colour in sections:
        items = stats.get(key, [])
        if items:
            print(f"\n  {b}{title}{r}")
            for label, cnt in items:
                bar = colour + "█" * min(cnt, 40) + r
                print(f"    {label:<26}  {bar}  {cnt}")

    print(f"{b}{'═'*56}{r}\n")


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description = "SIEM Collector  –  Phase 2  (sqlite3 + precise field extraction)",
        formatter_class = argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--db",    default=DB_PATH,
                   help=f"Path to SQLite database  (default: {DB_PATH})")
    p.add_argument("--poll",  type=float, default=2.0,
                   help="Event-log poll interval in seconds  (default: 2)")
    # Read-only inspection modes
    p.add_argument("--query",  action="store_true",
                   help="Print recent rows from the DB, then exit")
    p.add_argument("--limit",  type=int, default=25,
                   help="Rows to show with --query  (default: 25)")
    p.add_argument("--stats",  action="store_true",
                   help="Print threat-summary statistics, then exit")
    return p


def main() -> None:
    args = _build_parser().parse_args()

    with EventDatabase(args.db) as db:

        # ── Inspection modes (no live tail needed) ────────────────────────────
        if args.query:
            rows = db.fetch_recent(args.limit)
            _print_table(rows, title=f"Last {args.limit} Events  –  {args.db}")
            return

        if args.stats:
            _print_stats(db.fetch_stats())
            return

        # ── Live collection ───────────────────────────────────────────────────
        if not WIN32_AVAILABLE:
            log.error(
                "pywin32 is not installed.  Run:  pip install pywin32\n"
                "If on a non-Windows machine, use --query / --stats to inspect "
                "an existing database."
            )
            return

        log.info(
            "Collector started  |  DB: %s  |  Ctrl+C to stop.",
            os.path.abspath(args.db)
        )

        tailer = EventLogTailer(poll_interval=args.poll)

        for ev in tailer.tail():

            # ── Persist to SQLite  (Phase 2 core) ────────────────────────────
            try:
                row_id = db.insert_event(ev)
            except sqlite3.Error:
                row_id = None          # already logged inside insert_event()

            # ── Console feedback ──────────────────────────────────────────────
            print(_fmt_live(ev, row_id))


if __name__ == "__main__":
    main()