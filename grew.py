#!/usr/bin/env python3
"""grew — find out what is eating your disk, over time.

du and ncdu answer "what is big right now". Neither answers "what grew".
grew takes periodic snapshots of directory sizes and diffs them, so you can
ask what added 40GB since last week and get the specific directory to blame.
"""

from __future__ import annotations

import argparse
import codecs
import errno
import json
import math
import os
import random
import re
import shlex
import sqlite3
import stat
import sys
import time
from dataclasses import dataclass
from urllib.parse import quote

__version__ = "1.1.0"

SCHEMA_VERSION = 1

# Pseudo-filesystems that report meaningless sizes or recurse forever.
SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/tmp/.X11-unix"}


# --------------------------------------------------------------------------- #
# formatting
# --------------------------------------------------------------------------- #

def human(n: int, *, signed: bool = False) -> str:
    """Render a byte count the way a person reads it."""
    if signed:
        sign = "+" if n > 0 else ("-" if n < 0 else " ")
    else:
        sign = "-" if n < 0 else ""
    n = abs(n)
    if n < 1024:
        return f"{sign}{n}B"
    value = float(n)
    for unit in ("K", "M", "G", "T", "P", "E"):
        value /= 1024.0
        prec = 0 if value >= 100 else 1
        # Promote rather than print "1024K", which rounding would otherwise produce.
        if value < 1024 and float(f"{value:.{prec}f}") < 1024:
            return f"{sign}{value:.{prec}f}{unit}"
    return f"{sign}{value:.1f}E"


def parse_size(text: str) -> int:
    """'10M' -> 10485760. Accepts a bare byte count too."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([KMGTP]?)B?\s*", text, re.I)
    if not m:
        raise argparse.ArgumentTypeError(f"bad size: {text!r} (try 10M, 1G, 500K)")
    value, unit = float(m.group(1)), m.group(2).upper()
    size = value * (1024 ** "BKMGTP".index(unit or "B"))
    # A few hundred digits overflow float to inf, and int(inf) is an
    # OverflowError that argparse does not catch, so it would be a traceback.
    if not math.isfinite(size) or size >= 1 << 63:
        raise argparse.ArgumentTypeError(f"size too large: {text!r}")
    return int(size)


def positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a number, got {text!r}")
    if value < 0:
        raise argparse.ArgumentTypeError(f"must not be negative: {value}")
    return value


def parse_duration(text: str) -> float:
    """'7d' -> seconds. Supports s, m, h, d, w. Must be greater than zero."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhdw])\s*", text, re.I)
    if not m:
        raise argparse.ArgumentTypeError(f"bad duration: {text!r} (try 7d, 12h, 2w)")
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2).lower()]
    seconds = float(m.group(1)) * mult
    if not math.isfinite(seconds):
        raise argparse.ArgumentTypeError(f"duration too large: {text!r}")
    if seconds <= 0:
        # Zero reaches back no further than the latest snapshot, which would
        # silently compare it with itself and report "no growth".
        raise argparse.ArgumentTypeError(
            f"duration must be greater than zero: {text!r} (try 7d, 12h, 2w)")
    return seconds


def ago(seconds: float) -> str:
    seconds = max(0, seconds)
    for limit, div, unit in ((60, 1, "s"), (3600, 60, "m"), (86400, 3600, "h"),
                             (604800, 86400, "d"), (float("inf"), 604800, "w")):
        if seconds < limit:
            return f"{int(seconds / div)}{unit} ago"
    return "a while ago"


def duration_text(seconds: float) -> str:
    """The duration as it was asked for: 129600 -> '36h', 90 -> '90s', 0.5 -> '0.5s'.

    ago() floors to one unit, which would turn '--since 36h' into '1d' in a
    message about that very option.
    """
    for div, unit in ((604800, "w"), (86400, "d"), (3600, "h"), (60, "m")):
        if seconds >= div and seconds % div == 0:
            return f"{int(seconds // div)}{unit}"
    # :g would switch to exponent notation from a million seconds up ("1.23457e+06s").
    return f"{seconds:.6f}".rstrip("0").rstrip(".") + "s"


def printable(text: str, fallback: str) -> str:
    """`text` if stdout can encode it, else `fallback`.

    The arrow and the ellipsis are not in ASCII or Latin-1. Under such a
    locale (or PYTHONIOENCODING) printing them is a UnicodeEncodeError, so
    plain stand-ins are used instead.
    """
    name = getattr(sys.stdout, "encoding", None)
    if not name:
        return text            # a StringIO or similar: no encoding to fail
    try:
        text.encode(name)
    except (UnicodeEncodeError, LookupError):
        return fallback
    return text


# Terminal control characters: C0, DEL and C1, plus the surrogates that stand for the
# raw bytes 0x80-0x9f (an undecodable name written back out as those bytes).
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\udc80-\udc9f]")
_CONTROL_BUT_LAYOUT = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\udc80-\udc9f]")


def safe(text: str, *, layout: bool = False) -> str:
    """`text` with control characters spelled out (ESC becomes \\x1b), as ls -b does.

    A directory name is chosen by whoever can create it. Printed raw, an ESC in
    it can clear the screen or retitle the window, and a newline forges a line
    of output. --json is not affected: json.dumps escapes them already.
    `layout` keeps newline and tab, for a whole message rather than a name.
    """
    pattern = _CONTROL_BUT_LAYOUT if layout else _CONTROL
    return pattern.sub(lambda m: "\\x%02x" % (ord(m.group()) & 0xFF), text)


class Palette:
    """Colours, unless the output is piped or NO_COLOR is set."""

    def __init__(self, enabled: bool):
        self.on = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text

    def grow(self, t):   return self._wrap("31", t)   # red: using more disk
    def shrink(self, t): return self._wrap("32", t)   # green: freed space
    def dim(self, t):    return self._wrap("2", t)
    def bold(self, t):   return self._wrap("1", t)
    def head(self, t):   return self._wrap("1;36", t)


# --------------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------------- #

# Linux filenames are bytes, not text. Python surfaces undecodable bytes as
# surrogates, which sqlite and json both refuse to encode, so paths are stored
# as BLOBs and converted back on the way out.
enc = os.fsencode
dec = os.fsdecode

# How long to wait for another grew that is writing. A snapshot write is short,
# so this is generous; it is also how long concurrent first runs against a
# fresh database may queue while one of them creates the schema.
BUSY_SECONDS = 30.0

# BLOB, not TEXT: the code stores bytes (see above). Databases created by 1.0
# declared these TEXT; that still works, because SQLite keeps whatever type it
# was handed and snapshots_for() matches either form.
SCHEMA = (
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)",
    """CREATE TABLE IF NOT EXISTS snapshots (
        id INTEGER PRIMARY KEY,
        ts REAL NOT NULL,
        root BLOB NOT NULL,
        total INTEGER NOT NULL,
        files INTEGER NOT NULL,
        dirs INTEGER NOT NULL,
        errors INTEGER NOT NULL DEFAULT 0,
        elapsed REAL NOT NULL DEFAULT 0,
        apparent INTEGER NOT NULL DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS entries (
        snap INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
        path BLOB NOT NULL,
        bytes INTEGER NOT NULL,
        files INTEGER NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS entries_snap ON entries(snap)",
    "CREATE INDEX IF NOT EXISTS snapshots_root_ts ON snapshots(root, ts)",
)


def snap_row(row: sqlite3.Row) -> dict:
    """A snapshot row with its path decoded, safe for printing or JSON."""
    out = dict(row)
    out["root"] = dec(out["root"])
    return out


def data_dir() -> str:
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "grew")


def db_path(path: str | None) -> str:
    """Where the database lives. No side effects, so it is safe for messages."""
    if path is None:
        return os.path.join(data_dir(), "snapshots.db")
    if not path or "\0" in path:
        raise SystemExit("grew: --db needs a file name (not empty, no NUL bytes)")
    if path == ":memory:":
        # sqlite would open a private in-memory database: `snap` would report
        # success and the snapshot would vanish when the process exits.
        raise SystemExit("grew: --db :memory: would keep nothing, so grew refuses it.\n"
                         "      pass a file name, or ./:memory: for a file called that")
    return path


def failure_kind(exc: Exception) -> str:
    """Why sqlite failed: locked, readonly, full, corrupt or other.

    The advice differs completely by cause, and the wrong advice destroys data:
    a read-only or momentarily locked database is healthy, and telling someone
    to delete it because of a permissions problem would be a disaster.
    """
    msg = str(exc).lower()
    if "locked" in msg or "busy" in msg:
        return "locked"
    if "not a grew database" in msg:
        return "foreign"
    if ("readonly" in msg or "read-only" in msg or "unable to open" in msg
            or "permission" in msg):
        return "readonly"
    if "disk is full" in msg or "i/o error" in msg or "no space" in msg:
        return "full"
    if any(w in msg for w in ("not a database", "malformed", "corrupt", "encrypted",
                              "no such table", "no such column")):
        return "corrupt"
    return "other"


def db_failure(path: str, exc: Exception, doing: str = "use") -> SystemExit:
    """A SystemExit whose advice matches the cause. Never says "delete it"."""
    quoted = safe(shlex.quote(path))
    path = safe(path)
    advice = {
        "locked": "another grew is probably writing to it. wait a moment and try again.",
        "readonly": "grew has no permission to use it there. check the permissions on the\n"
                    "      file and its directory (list, top and growth need to read it;\n"
                    "      snap and prune need to write) and that the filesystem is not\n"
                    "      mounted read-only, or pass --db FILE for another one.",
        "foreign": "that is another program's SQLite database, so grew left it alone.\n"
                   "      pass --db FILE to keep grew's snapshots in a file of their own.",
        "full": "the disk is full or failing, not the database. free some space, or\n"
                "      pass --db FILE on another filesystem.",
        "corrupt": "the file looks corrupt, or is not a grew database. move it aside\n"
                   f"      (mv {quoted} {quoted}.bad) and snapshot again, or pass --db FILE\n"
                   "      for a new one. grew never deletes it for you.",
        "other": "unexpected database error. try again, or pass --db FILE to use a\n"
                 "      different file.",
    }[failure_kind(exc)]
    return SystemExit(f"grew: cannot {doing} database {path}\n      {exc}\n      {advice}")


def ensure_db_dir(path: str, explicit: bool) -> None:
    """Create the database's directory, or exit saying what to change."""
    folder = os.path.dirname(os.path.abspath(path)) or "."
    try:
        # 0700 for the leaf: the database lists the large directories of the
        # disk, which is nobody else's business. An existing directory is left
        # as it is.
        os.makedirs(folder, mode=0o700, exist_ok=True)
    except (OSError, ValueError) as exc:
        hint = ("pass a different --db FILE" if explicit
                else "set XDG_DATA_HOME to a writable directory or pass --db FILE")
        raise SystemExit(f"grew: cannot create database directory {safe(folder)}: {exc}\n"
                         f"      {hint}")


def create_db_file(path: str, explicit: bool) -> None:
    """Create the empty database file readable by its owner only (0600, less the umask).

    sqlite would create it with the default mode, 0644 under the usual umask,
    and copies that mode onto the -wal and -shm files. Creating it first, with
    O_CREAT and no O_TRUNC, is also safe when several grews start together.
    """
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600))
    except OSError as exc:
        if exc.errno == errno.EROFS:
            cause = "the filesystem is mounted read-only. remount it read-write, or"
        else:
            cause = "check the permissions and free space there, or"
        hint = "pass a different --db FILE" if explicit \
            else "set XDG_DATA_HOME elsewhere or pass --db FILE"
        raise SystemExit(f"grew: cannot create database {safe(path)}: "
                         f"{exc.strerror or exc}\n      {cause} {hint}")


class Connection(sqlite3.Connection):
    """A connection that can say which file it stands in for (see _empty_db)."""

    stands_in_for: str | None = None


def _open(target: str, *, uri: bool = False) -> sqlite3.Connection:
    # The busy timeout is set here, before anything else touches the file, so
    # even the very first statement waits for a racing process rather than
    # failing at once.
    db = sqlite3.connect(target, timeout=BUSY_SECONDS, uri=uri, factory=Connection)
    db.row_factory = sqlite3.Row
    return db


def _objects(db: sqlite3.Connection) -> set[str]:
    return {r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('table', 'index')")}


# Everything grew itself creates. Anything else in the file belongs to someone else.
GREW_OBJECTS = {"meta", "snapshots", "entries", "entries_snap", "snapshots_root_ts"}


def _check_schema(db: sqlite3.Connection, path: str, objects: set[str]) -> None:
    """Refuse a database written by a newer grew or by another program.

    Done before anything is written, so a refused file is left exactly as it was.
    A table called `meta` proves nothing (key/value tables of that name are
    common), so grew's own shape is checked: columns key and value, a `schema`
    row with a number, nothing else in the table and no foreign tables.
    """
    ours = {name for name in objects if not name.startswith("sqlite_")}
    if not ours:
        return
    foreign = sqlite3.DatabaseError("file is not a grew database: it has tables "
                                    "that grew did not create")
    # CREATE TABLE IF NOT EXISTS would add grew's tables to someone else's
    # database, and reading it would claim "no snapshots yet".
    if "meta" not in ours:
        raise foreign
    if [r[1] for r in db.execute("PRAGMA table_info(meta)")] != ["key", "value"]:
        raise foreign
    if db.execute("SELECT COUNT(*) FROM meta WHERE key IS NOT 'schema'").fetchone()[0]:
        raise foreign                  # grew keeps nothing else in there
    row = db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
    if row is None:
        # grew writes the version in the transaction that creates the tables,
        # so tables without it were made by somebody else. A bare, empty meta is
        # an initialisation that never got further, and is ours.
        if ours != {"meta"}:
            raise foreign
        return
    text = str(row["value"])
    found = int(text) if re.fullmatch("[0-9]+", text) else SCHEMA_VERSION
    if found > SCHEMA_VERSION:
        raise SystemExit(
            f"grew: database {safe(path)} uses schema v{found}, but this grew only\n"
            f"      understands v{SCHEMA_VERSION}. upgrade grew, or use --db for a new file.")
    if ours - GREW_OBJECTS:
        raise foreign


def _initialise(db: sqlite3.Connection, path: str) -> None:
    """Make the database ready for writing, safely when several grews race.

    Cron jobs and parallel runs can all hit a fresh file at once. Each step
    that can lose such a race is retried: switching to WAL needs a lock that
    others may hold, and sqlite does not always wait for it. The schema is
    created inside one short write transaction, which also serialises the
    racers and proves up front that the file is writable.
    """
    deadline = time.monotonic() + BUSY_SECONDS
    while True:
        try:
            objects = _objects(db)
            _check_schema(db, path, objects)          # before any write
            if db.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                db.execute("PRAGMA journal_mode=WAL")
            db.execute("BEGIN IMMEDIATE")
            for statement in SCHEMA:
                db.execute(statement)
            db.execute("INSERT OR IGNORE INTO meta VALUES ('schema', ?)",
                       (str(SCHEMA_VERSION),))
            db.commit()
            return
        except sqlite3.OperationalError as exc:
            if db.in_transaction:
                db.rollback()
            if failure_kind(exc) != "locked" or time.monotonic() >= deadline:
                raise
            time.sleep(random.uniform(0.02, 0.15))


def _open_readonly(path: str) -> tuple[sqlite3.Connection, set[str]]:
    """Open for reading without needing to write, even to a read-only database.

    When the file and its directory are writable, an ordinary connection is
    best: a WAL database's -wal and -shm files are then tidied away on close.
    A mode=ro connection cannot delete them, so on a WAL database it would
    leave two stray files behind after every `grew list`. A file we cannot
    write is therefore read with immutable=1, which creates nothing and reads
    the file as it stands. That is only right when no -wal, -shm or -journal
    sits beside it (they would hold changes immutable ignores), so then
    mode=ro is used instead, which does honour them.
    """
    absolute = os.path.abspath(path)
    location = quote(enc(absolute))
    ordinary = (path, False)
    read_only = (f"file:{location}?mode=ro", True)
    immutable = (f"file:{location}?immutable=1", True)
    folder = os.path.dirname(absolute)
    if os.access(path, os.W_OK) and os.access(folder, os.W_OK | os.X_OK):
        targets = [ordinary, read_only, immutable]
    elif any(os.path.lexists(absolute + tail) for tail in ("-wal", "-shm", "-journal")):
        targets = [read_only, immutable]
    else:
        targets = [immutable, read_only]
    last: Exception | None = None
    for target, uri in targets:
        db = None
        try:
            db = _open(target, uri=uri)
            return db, _objects(db)
        except sqlite3.Error as exc:
            if db is not None:
                db.close()
            # "readonly" is the expected reason to try the next way in. "full" is
            # sqlite's "disk I/O error", which an ordinary connection also gets
            # when it cannot create -wal and -shm (a file-size limit, say) and
            # which immutable=1 does not need to.
            if failure_kind(exc) not in ("readonly", "full"):
                raise
            last = exc
    assert last is not None
    raise last


def mounted_read_only(path: str) -> bool:
    """True if the filesystem holding `path` is mounted read-only."""
    try:
        return bool(os.statvfs(path).f_flag & getattr(os, "ST_RDONLY", 1))
    except (OSError, AttributeError):
        return False


def _check_writable(path: str) -> None:
    """Refuse a database this process cannot write, before opening it.

    Opening a read-only WAL database for writing makes sqlite create -wal and
    -shm beside it (copying the file's mode, so read-only too) and only then
    fail. Those leftovers keep the database unwritable after the file itself
    is fixed, and nothing in sqlite's message points at them. Not opening it
    leaves nothing behind. A leftover that is already read-only is named, and
    so is a read-only mount: os.access says no for both, but chmod only helps
    with the first.
    """
    for candidate in (path, path + "-wal", path + "-shm"):
        if not os.path.lexists(candidate) or os.access(candidate, os.W_OK):
            continue
        # os.access also says "no" for a file that has just gone, and a racing
        # grew closing its connection removes -wal and -shm. Ask again.
        if os.path.lexists(candidate):
            if mounted_read_only(candidate):
                raise SystemExit(
                    f"grew: cannot write database {safe(path)}\n"
                    "      the filesystem it is on is mounted read-only, and changing the\n"
                    "      file's permissions will not help. remount it read-write, or pass\n"
                    "      --db FILE for a database on another filesystem.")
            quoted = safe(shlex.quote(candidate))
            what = "the file" if candidate == path else "the leftover file beside it"
            raise SystemExit(
                f"grew: cannot write database {safe(path)}\n"
                f"      {what} {safe(candidate)} is read-only. check its permissions and make "
                f"it writable\n      (chmod u+w {quoted}), or pass --db FILE for another "
                "one.")


def _empty_db(stands_in_for: str | None = None) -> sqlite3.Connection:
    """An in-memory database with the schema, for 'nothing recorded yet'.

    `stands_in_for` is the file that was looked for, so the message can name it:
    a mistyped --db otherwise reads exactly like a first run.
    """
    db = _open(":memory:")
    db.stands_in_for = stands_in_for
    for statement in SCHEMA:
        db.execute(statement)
    return db


def connect(path: str | None = None, *, readonly: bool = False,
            create: bool = True) -> sqlite3.Connection:
    """Open the snapshot database.

    readonly: only read it; nothing is written, so a read-only file or
        directory works. create: make the file if missing. When it is missing
        and either flag says not to, an empty in-memory database stands in, so
        "no snapshots yet" can be reported without leaving a file behind.
    """
    explicit = path is not None
    target = db_path(path)

    try:
        info = os.stat(target)
    except (FileNotFoundError, NotADirectoryError):
        exists = False
    except OSError as exc:
        if exc.errno == errno.ENAMETOOLONG:
            advice = "the file name or a directory name in it is too long. pass a shorter --db FILE"
        else:
            advice = "check its permissions, or pass --db FILE"
        raise SystemExit(f"grew: cannot access database {safe(target)}: "
                         f"{exc.strerror or exc}\n      {advice}")
    else:
        if stat.S_ISDIR(info.st_mode):
            if explicit:
                raise SystemExit(f"grew: --db must be a file, not a directory: {safe(target)}")
            raise SystemExit(f"grew: {safe(target)} is a directory, but grew needs a file there.\n"
                             "      move it, set XDG_DATA_HOME elsewhere, or pass --db FILE")
        if not stat.S_ISREG(info.st_mode):
            # /dev/null, a FIFO or a socket: sqlite's own error would blame
            # permissions or a full disk, and neither is the problem.
            raise SystemExit(f"grew: {safe(target)} is not a regular file, so it cannot hold a "
                             "database.\n      pass --db FILE with the name of an ordinary file")
        if not os.access(target, os.R_OK):
            raise SystemExit(f"grew: cannot read database {safe(target)}: permission denied\n"
                             "      check its permissions, or pass --db FILE")
        exists = True

    if not exists:
        if readonly or not create:
            return _empty_db(target)
        ensure_db_dir(target, explicit)
        create_db_file(target, explicit)
    elif info.st_size == 0 and (readonly or not create):
        # An empty file (touch, mktemp) is a database with nothing in it. Leave
        # it empty; only snap fills it in.
        return _empty_db(target)

    db = None
    try:
        if readonly:
            db, objects = _open_readonly(target)
            _check_schema(db, target, objects)
            if not {"snapshots", "entries"} <= objects:
                # No tables (or only meta, from an initialisation that never
                # finished): nothing was ever recorded. A missing *index* is not
                # the same thing, and must not hide the rows that are there.
                db.close()
                return _empty_db(target)
        else:
            if exists:
                _check_writable(target)
            db = _open(target)
            _initialise(db, target)
        return db
    except sqlite3.Error as exc:
        if db is not None:
            db.close()
        raise db_failure(target, exc)
    except SystemExit:
        if db is not None:
            db.close()
        raise


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #

@dataclass
class ScanResult:
    sizes: dict[str, int]
    counts: dict[str, int]
    total: int
    files: int
    errors: int


def scan(root: str, *, apparent: bool = False, one_fs: bool = True,
         min_size: int = 1 << 20, max_depth: int | None = None,
         exclude: list[str] | None = None) -> ScanResult:
    """Walk `root` and return cumulative bytes per directory.

    Counts allocated blocks by default, which is what actually consumes the
    disk; `apparent` switches to logical file size. Hardlinked files are
    counted once. Directories smaller than `min_size` are dropped from the
    result so stored snapshots stay small.
    """
    root = abs_root(root)
    exclude = [os.path.abspath(p) for p in (exclude or [])]
    root_dev = os.stat(root).st_dev
    seen_inodes: set[tuple[int, int]] = set()

    sizes: dict[str, int] = {}
    counts: dict[str, int] = {}
    errors = 0

    def skip(path: str) -> bool:
        if path in SKIP_DIRS:
            return True
        return any(path == e or path.startswith(e + os.sep) for e in exclude)

    def own_size(path: str) -> int:
        # A directory's own inode occupies space too; du counts it, so do we.
        # Apparent mode is different: du --apparent-size (and -b) leave
        # directories out, and a directory's st_size is a filesystem artefact
        # anyway (4096 on ext4, 40 + 20 per entry on tmpfs).
        if apparent:
            return 0
        try:
            return os.stat(path, follow_symlinks=False).st_blocks * 512
        except OSError:
            return 0

    def open_frame(path: str) -> list:
        """Read a directory fully, then close it.

        Holding the handle open while descending would keep one file
        descriptor per level, and a tree ~1000 deep silently exhausts the
        default limit of 1024 — producing an undercount rather than an error.
        Reading eagerly costs memory proportional to the widest directory,
        which is the better trade.
        """
        nonlocal errors
        try:
            with os.scandir(path) as it:
                entries = list(it)
        except OSError:
            errors += 1
            entries = []
        return [path, entries, 0, own_size(path), 0]

    # Explicit stack rather than recursion: real filesystems nest deeper than
    # Python's recursion limit, and a RecursionError mid-scan loses everything.
    PATH, ENTRIES, POS, SIZE, FILES = 0, 1, 2, 3, 4
    stack = [open_frame(root)]
    total = files = 0

    while stack:
        frame = stack[-1]
        descended = False

        while frame[POS] < len(frame[ENTRIES]):
            entry = frame[ENTRIES][frame[POS]]
            frame[POS] += 1

            try:
                if entry.is_symlink():
                    # Never follow one (that would double-count and can loop),
                    # but the link's own inode occupies disk, and du counts it.
                    st = entry.stat(follow_symlinks=False)
                    if st.st_nlink > 1:
                        # A symlink can be hardlinked too (ln -P), and du counts
                        # its inode once, like any other non-directory.
                        key = (st.st_dev, st.st_ino)
                        if key in seen_inodes:
                            continue
                        seen_inodes.add(key)
                    frame[SIZE] += st.st_size if apparent else st.st_blocks * 512
                    frame[FILES] += 1
                    continue
                if entry.is_dir(follow_symlinks=False):
                    child = entry.path
                    if skip(child):
                        continue
                    if one_fs and entry.stat(follow_symlinks=False).st_dev != root_dev:
                        continue
                    stack.append(open_frame(child))
                    descended = True
                    break
                if entry.is_file(follow_symlinks=False):
                    st = entry.stat(follow_symlinks=False)
                    if one_fs and st.st_dev != root_dev:
                        # A file can be a mount point too (Docker bind-mounts
                        # /etc/hosts), and du -x leaves it out like a directory.
                        continue
                    if st.st_nlink > 1:
                        key = (st.st_dev, st.st_ino)
                        if key in seen_inodes:
                            continue
                        seen_inodes.add(key)
                    frame[SIZE] += st.st_size if apparent else st.st_blocks * 512
                    frame[FILES] += 1
            except (OSError, ValueError):
                errors += 1

        if descended:
            continue

        done = stack.pop()
        depth = len(stack)
        if done[SIZE] >= min_size and (max_depth is None or depth <= max_depth):
            sizes[done[PATH]] = done[SIZE]
            counts[done[PATH]] = done[FILES]
        if stack:
            stack[-1][SIZE] += done[SIZE]
            stack[-1][FILES] += done[FILES]
        else:
            total, files = done[SIZE], done[FILES]

    sizes[root] = total          # the root is always recorded
    counts[root] = files
    return ScanResult(sizes, counts, total, files, errors)


# --------------------------------------------------------------------------- #
# diffing
# --------------------------------------------------------------------------- #

@dataclass
class Change:
    path: str
    before: int
    after: int

    @property
    def delta(self) -> int:
        return self.after - self.before

    @property
    def is_new(self) -> bool:
        return self.before == 0 and self.after > 0

    @property
    def is_gone(self) -> bool:
        return self.after == 0 and self.before > 0


def diff(before: dict[str, int], after: dict[str, int],
         *, threshold: int = 0) -> list[Change]:
    changes = []
    for path in set(before) | set(after):
        a, b = before.get(path, 0), after.get(path, 0)
        if abs(b - a) > threshold:
            changes.append(Change(path, a, b))
    # Ties are broken by path: the changes come out of a set, whose order varies
    # with string hashing, so equal deltas would otherwise print (and, under
    # -n, be cut) differently on every run.
    changes.sort(key=lambda c: (-abs(c.delta), c.path))
    return changes


def blame(changes: list[Change], *, explain: float = 0.9) -> list[Change]:
    """Collapse a chain of parents onto the directory actually responsible.

    Sizes are cumulative, so a 10GB build directory also inflates every
    directory above it. Reporting all of them is noise. If a single child
    accounts for `explain` of a parent's change, the parent is dropped and
    only the specific culprit is reported.
    """
    by_path = {c.path: c for c in changes}
    # Largest same-direction change found beneath each path.
    best: dict[str, int] = {}

    # Walking up from each change is O(depth) per entry. Comparing every pair
    # instead is O(n^2), which is seconds of stall on a real home directory.
    for c in changes:
        if c.delta == 0:
            continue
        magnitude = abs(c.delta)
        growing = c.delta > 0
        parent = os.path.dirname(c.path)
        previous = None
        while parent != previous:
            ancestor = by_path.get(parent)
            if ancestor is not None and (ancestor.delta > 0) == growing:
                if magnitude > best.get(parent, 0):
                    best[parent] = magnitude
            previous = parent
            parent = os.path.dirname(parent)

    return [c for c in changes if best.get(c.path, 0) < abs(c.delta) * explain]


# --------------------------------------------------------------------------- #
# db helpers
# --------------------------------------------------------------------------- #

def note(text: str) -> None:
    """A courtesy message on stderr: progress, a fallback, a note after the work.

    Best effort. With stderr closed, sys.stderr is None and print(file=None)
    would write to *stdout*, which for --json is somebody's parser input. With
    stderr full, failing to print a note must not fail work that succeeded.
    """
    if sys.stderr is None:
        return
    try:
        print(text, file=sys.stderr, flush=True)
    except (OSError, ValueError):
        silence(sys.stderr)


# SQLite integers are 64-bit; a bigger LIMIT is an OverflowError, not an error
# message, and nobody has that many rows anyway.
MAX_ROWS = (1 << 62)


def abs_root(path: str) -> str:
    """The absolute directory a path names, the way the kernel reads it.

    os.path.abspath folds `..` textually, so `lnk/..` (lnk being a symlink to
    ../real/deep) became the current directory, while the kernel, du and ls
    take it to ../real. A path with `..` in it is therefore resolved properly;
    any other is only made absolute, so a root that is itself a symlink keeps
    the name the user gave it.
    """
    if ".." in path.split(os.sep):
        return os.path.realpath(path)
    return os.path.abspath(path)


def save_snapshot(db, root: str, res: ScanResult, elapsed: float, apparent: bool) -> int:
    cur = db.execute(
        "INSERT INTO snapshots (ts, root, total, files, dirs, errors, elapsed, apparent)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (time.time(), enc(root), res.total, res.files, len(res.sizes),
         res.errors, elapsed, int(apparent)),
    )
    snap_id = cur.lastrowid
    db.executemany(
        "INSERT INTO entries (snap, path, bytes, files) VALUES (?,?,?,?)",
        [(snap_id, enc(p), b, res.counts.get(p, 0)) for p, b in res.sizes.items()],
    )
    db.commit()
    return snap_id


def load_entries(db, snap_id: int) -> dict[str, int]:
    return {dec(r["path"]): r["bytes"]
            for r in db.execute("SELECT path, bytes FROM entries WHERE snap=?", (snap_id,))}


def snapshots_for(db, root) -> list[sqlite3.Row]:
    if root:
        key = enc(abs_root(dec(root)))
        # CAST makes a root stored as TEXT (databases from before the column
        # was declared BLOB) match the same way as one stored as bytes.
        return list(db.execute(
            "SELECT * FROM snapshots WHERE CAST(root AS BLOB)=? ORDER BY ts, id", (key,)))
    return list(db.execute("SELECT * FROM snapshots ORDER BY ts, id"))


def nothing_recorded(db, path: str | None) -> str:
    """Say why there is nothing to show, naming the path and where else to look."""
    # A database that is not there (or is an empty file) reads like a first run,
    # unless the file is named: a mistyped --db otherwise looks the same.
    looked = getattr(db, "stands_in_for", None)
    where = f" in {safe(looked)}" if looked else ""
    if not path:
        return f"no snapshots yet{where}. run `grew snap <path>` first."
    shown = safe(abs_root(path))
    roots = {dec(r["root"]) for r in db.execute("SELECT root FROM snapshots")}
    if not roots:
        return f"no snapshots yet{where}. run `grew snap {shown}` first."
    n = len(roots)
    return (f"no snapshots of {shown} yet. {n} other root{'' if n == 1 else 's'} "
            f"{'has' if n == 1 else 'have'} snapshots (see `grew list`),\n"
            f"      or run `grew snap {shown}` to start one.")


def pick_pair(db, root: str | None, since: float | None, frm: int | None,
              to: int | None) -> tuple[sqlite3.Row, sqlite3.Row, bool]:
    """Choose which two snapshots to compare.

    The third value is True when --since reached further back than the history
    and the oldest snapshot was used instead.
    """
    if frm is not None or to is not None:
        if frm is None or to is None:
            raise SystemExit("grew: --from and --to must be given together")
        rows = {r["id"]: r for r in db.execute("SELECT * FROM snapshots")}
        if frm not in rows or to not in rows:
            raise SystemExit("grew: no snapshot with that id (try `grew list`)")
        if frm == to:
            # Comparing a snapshot with itself always reports "no growth".
            raise SystemExit(
                f"grew: --from and --to are the same snapshot (#{frm}), so there is\n"
                "      nothing to compare. give two different ids (see `grew list`).")
        a, b = rows[frm], rows[to]
        if dec(a["root"]) != dec(b["root"]):
            raise SystemExit(
                f"grew: those snapshots cover different directories\n"
                f"      #{frm} is {safe(dec(a['root']))}\n"
                f"      #{to} is {safe(dec(b['root']))}")
        return a, b, False

    # With several roots in one database, default to the most recently
    # snapshotted one rather than silently diffing unrelated directories.
    if not root:
        recent = snapshots_for(db, None)
        if recent:
            root = recent[-1]["root"]
    snaps = snapshots_for(db, root)
    if len(snaps) < 2:
        raw = abs_root(dec(root)) if root else None
        shown = safe(raw) if raw else None
        where = f" of {shown}" if shown else ""
        if snaps:
            why = f"grew: need at least two snapshots{where} to compare.\n"
        else:
            why = (f"grew: {nothing_recorded(db, raw)}\n"
                   f"      need at least two snapshots{where} to compare.\n")
        raise SystemExit(
            why + f"      run `grew snap {shown or '<path>'}` now, and again later.")
    latest = snaps[-1]
    if since is None:
        return snaps[-2], latest, False

    cutoff = latest["ts"] - since
    # Never the latest itself: a duration too small to move a Unix timestamp
    # (1e-10s) leaves cutoff == latest["ts"], and the latest would then be
    # "older than itself" and compared with itself.
    older = [s for s in snaps[:-1] if s["ts"] <= cutoff]
    # Fall back to the oldest we have rather than failing outright.
    return (older[-1] if older else snaps[0]), latest, not older


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def cmd_snap(args, db, pal) -> int:
    root = abs_root(args.path)
    shown = safe(root)
    try:
        is_dir = stat.S_ISDIR(os.stat(root).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        raise SystemExit(f"grew: not a directory: {shown} (it does not exist)")
    except PermissionError:
        # os.path.isdir would call this "not a directory", which is the wrong
        # cause. (A directory that can be reached but not listed is different:
        # the scan counts it as unreadable and carries on.)
        raise SystemExit(f"grew: cannot reach {shown}: permission denied\n"
                         "      a directory above it cannot be searched. check its permissions")
    except OSError as exc:
        raise SystemExit(f"grew: cannot access {shown}: {exc.strerror or exc}")
    if not is_dir:
        raise SystemExit(f"grew: not a directory: {shown}")

    # A relative --exclude is taken from the current directory, like any other
    # path argument, not from the snapshot root. One that names nothing inside
    # the root excludes nothing, and the snapshot would quietly include what the
    # user meant to leave out, so say so. Also under -q: a cron job with a wrong
    # path should be heard.
    for given in args.exclude:
        path = os.path.abspath(given)
        if path != root and not path.startswith(root.rstrip(os.sep) + os.sep):
            note(f"grew: note: --exclude {safe(given)} is not inside {shown}, so it excludes "
                 f"nothing\n      (relative paths are taken from the current directory, "
                 f"here {safe(os.getcwd())})")
        elif not os.path.lexists(path):
            note(f"grew: note: --exclude {safe(given)} does not exist, so it excludes nothing")

    if not args.quiet:
        note(f"scanning {pal.bold(shown)} ...")

    start = time.time()
    res = scan(root, apparent=args.apparent, one_fs=not args.cross_filesystem,
               min_size=args.min_size, max_depth=args.depth, exclude=args.exclude)
    elapsed = time.time() - start
    snap_id = save_snapshot(db, root, res, elapsed, args.apparent)

    # The snapshot is committed. Failing to *print* it (a full or closed stdout)
    # must not make a cron job think there is no snapshot.
    try:
        if args.json:
            print(json.dumps({"id": snap_id, "root": root, "total": res.total,
                              "files": res.files, "dirs": len(res.sizes),
                              "errors": res.errors, "elapsed": round(elapsed, 3)}))
        elif not args.quiet:
            unreadable = f"  ({res.errors} unreadable)" if res.errors else ""
            print(f"snapshot {pal.bold('#' + str(snap_id))}  "
                  f"{pal.bold(human(res.total))} across {res.files:,} files"
                  f"{pal.dim(unreadable)}  {elapsed:.1f}s")
            prior = snapshots_for(db, root)
            if len(prior) >= 2:
                print(pal.dim("compare with: grew growth"))
        if sys.stdout is not None:
            sys.stdout.flush()
    except BrokenPipeError:
        raise                   # main() ends quietly, as for every command
    except OSError as exc:
        silence_stdout()
        note(f"grew: note: snapshot #{snap_id} was saved, but its summary could "
             f"not be written: {exc}")
    return 0


def cmd_growth(args, db, pal) -> int:
    a, b, fell_back = pick_pair(db, args.path, args.since, args.from_id, args.to_id)
    if fell_back:
        # stderr, so --json output stays clean for whatever is parsing it.
        note(f"grew: note: no snapshot is {duration_text(args.since)} old yet; "
             f"comparing with the oldest, #{a['id']} "
             f"({ago(time.time() - a['ts'])}).")

    if a["apparent"] != b["apparent"]:
        raise SystemExit(
            "grew: those two snapshots measure size differently, so any\n"
            "      difference between them would be meaningless.\n"
            f"      #{a['id']} used {'apparent size' if a['apparent'] else 'allocated blocks'}, "
            f"#{b['id']} used {'apparent size' if b['apparent'] else 'allocated blocks'}.\n"
            "      take both snapshots the same way, with or without --apparent.")

    before, after = load_entries(db, a["id"]), load_entries(db, b["id"])
    changes = diff(before, after, threshold=args.min_size)
    if not args.all:
        changes = blame(changes)
    shrunk = 0
    if not args.shrink:
        shrunk = sum(1 for c in changes if c.delta < 0)
        changes = [c for c in changes if c.delta > 0]

    span = b["ts"] - a["ts"]
    net = b["total"] - a["total"]

    if args.json:
        print(json.dumps({
            "root": dec(b["root"]),
            "from": {"id": a["id"], "ts": a["ts"], "total": a["total"]},
            "to": {"id": b["id"], "ts": b["ts"], "total": b["total"]},
            "net": net,
            "changes": [{"path": c.path, "before": c.before,
                         "after": c.after, "delta": c.delta}
                        for c in changes[: args.top]],
        }, indent=2))
        return 0

    colour = pal.grow if net > 0 else pal.shrink
    arrow = printable("→", "->")
    ellipsis = printable("…", "...")
    print(f"{pal.head(safe(dec(b['root'])))}")
    ids = f"#{a['id']} {arrow} #{b['id']}"
    print(f"  {pal.dim(ids)}  "
          f"over {ago(span).replace(' ago', '')}  "
          f"net {colour(human(net, signed=True))}  "
          f"(now {human(b['total'])})")

    if not changes:
        if shrunk:
            # Without --shrink the shrinking directories are filtered out, so
            # "nothing changed" would contradict a header showing a big net drop.
            print(pal.dim(f"\n  nothing grew by more than {human(args.min_size)}, but "
                          f"{shrunk} director{'y' if shrunk == 1 else 'ies'} shrank "
                          "(--shrink shows them)"))
        else:
            print(pal.dim("\n  nothing changed by more than " + human(args.min_size)))
        return 0

    print()
    shown_paths = {c.path: safe(c.path) for c in changes[: args.top]}
    width = max((len(p) for p in shown_paths.values()), default=20)
    width = min(width, 70)
    for c in changes[: args.top]:
        tag = ""
        if c.is_new:
            tag = pal.dim(" new")
        elif c.is_gone:
            tag = pal.dim(" gone")
        mark = pal.grow if c.delta > 0 else pal.shrink
        full = shown_paths[c.path]
        path = (full if len(full) <= width
                else ellipsis + full[-(width - len(ellipsis)):])
        # Pad the visible text first, then colour it: the escape codes are
        # invisible but count as characters, so padding a coloured string
        # leaves the columns ragged.
        delta = f"{human(c.delta, signed=True):>12}"
        move = f"{human(c.before)} {arrow} {human(c.after)}"
        print(f"  {mark(delta)}  {path:<{width}}  {pal.dim(move)}{tag}")

    hidden = len(changes) - args.top
    if hidden > 0:
        print(pal.dim(f"\n  {hidden} more (use --top {len(changes)} to see all)"))
    if not args.all:
        print(pal.dim("  parents explained by a single child are hidden; --all shows them"))
    return 0


def cmd_top(args, db, pal) -> int:
    snaps = snapshots_for(db, args.path)
    if not snaps:
        raise SystemExit(f"grew: {nothing_recorded(db, args.path)}")
    snap = snaps[-1]
    rows = list(db.execute(
        "SELECT path, bytes, files FROM entries WHERE snap=? ORDER BY bytes DESC, path"
        " LIMIT ?",
        (snap["id"], min(args.top, MAX_ROWS))))

    if args.json:
        print(json.dumps([{**dict(r), "path": dec(r["path"])} for r in rows], indent=2))
        return 0

    print(f"{pal.head(safe(dec(snap['root'])))}  {pal.dim(ago(time.time() - snap['ts']))}  "
          f"total {pal.bold(human(snap['total']))}\n")
    width = min(max((len(safe(dec(r["path"]))) for r in rows), default=20), 70)
    ellipsis = printable("…", "...")
    for r in rows:
        full = safe(dec(r["path"]))
        path = full if len(full) <= width else ellipsis + full[-(width - len(ellipsis)):]
        n = r['files']
        files_label = f"{n:,} file" + ("" if n == 1 else "s")
        print(f"  {human(r['bytes']):>10}  {path:<{width}}  {pal.dim(files_label)}")
    return 0


def cmd_list(args, db, pal) -> int:
    snaps = snapshots_for(db, args.path)
    if args.json:
        print(json.dumps([snap_row(s) for s in snaps], indent=2))
        return 0
    if not snaps:
        # Exit 0: an empty list is a valid answer, unlike `top`, which has
        # nothing to show and says so with a failure.
        print(pal.dim(nothing_recorded(db, args.path)))
        return 0
    print(pal.dim(f"  {'id':>4}  {'when':<12} {'total':>10}   root"))
    # (total, apparent) of the previous snapshot of each root. A change is only
    # shown between snapshots measured the same way: an --apparent total minus
    # an allocated one is a number with no meaning, which growth refuses too.
    prev_by_root: dict[str, tuple[int, int]] = {}
    for s in snaps:
        root = dec(s["root"])
        delta = ""
        prev = prev_by_root.get(root)
        if prev is not None and prev[1] == s["apparent"]:
            d = s["total"] - prev[0]
            if d:
                colour = pal.grow if d > 0 else pal.shrink
                delta = "  " + colour(human(d, signed=True))
        prev_by_root[root] = (s["total"], s["apparent"])
        print(f"  {s['id']:>4}  {ago(time.time() - s['ts']):<12} "
              f"{human(s['total']):>10}   {safe(root)}{delta}")
    return 0


def cmd_prune(args, db, pal) -> int:
    snaps = snapshots_for(db, args.path)
    # --keep is per directory. Without a path, one budget shared by every root
    # would let a busy directory push all of a quieter one's history out.
    by_root: dict[str, list] = {}
    for s in snaps:
        by_root.setdefault(dec(s["root"]), []).append(s)
    ids = sorted(s["id"] for group in by_root.values()
                 for s in group[: max(0, len(group) - args.keep)])
    per_root = f" per directory ({len(by_root)} of them)" if len(by_root) > 1 else ""
    # Older sqlite caps the number of ? in one statement at 999.
    for i in range(0, len(ids), 500):
        batch = ids[i:i + 500]
        qs = ",".join("?" * len(batch))
        db.execute(f"DELETE FROM entries WHERE snap IN ({qs})", batch)
        db.execute(f"DELETE FROM snapshots WHERE id IN ({qs})", batch)
    db.commit()
    kept = len(snaps) - len(ids)

    reclaimed = True
    if ids:
        try:
            db.execute("VACUUM")
        except sqlite3.Error as exc:
            # The snapshots are already gone. Failing to give the space back
            # (a reader holds the file, or the disk is tight) is not an error.
            reclaimed = False
            if not args.quiet:
                note(f"grew: note: removed the rows but could not shrink the file: {exc}")

    # The rows are gone and committed. Failing to print the result (a full or
    # closed stdout) must not make a cron job think the prune failed.
    try:
        if args.json:
            print(json.dumps({"root": abs_root(args.path) if args.path else None,
                              "removed": len(ids), "ids": ids,
                              "kept": kept, "keep": args.keep, "reclaimed": reclaimed}))
        elif args.quiet:
            pass
        elif not snaps and args.path:
            note(pal.dim(nothing_recorded(db, args.path)))
        elif not ids:
            print(pal.dim(f"nothing to prune ({len(snaps)} snapshots, "
                          f"keeping {args.keep}{per_root})"))
        else:
            print(f"removed {len(ids)} snapshot(s), kept {kept}"
                  + (f" (--keep {args.keep}{per_root})" if per_root else ""))
        if sys.stdout is not None:
            sys.stdout.flush()
    except BrokenPipeError:
        raise                   # main() ends quietly, as for every command
    except OSError as exc:
        silence_stdout()
        note(f"grew: note: the prune was done ({len(ids)} removed), but its result "
             f"could not be written: {exc}")
    return 0


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #

def global_options(*, after_command: bool) -> argparse.ArgumentParser:
    """--db, --json and --no-color, accepted before or after the subcommand.

    The copy on each subparser defaults to SUPPRESS: otherwise argparse would
    overwrite a value given before the subcommand with the subparser's default.
    """
    extra = {"default": argparse.SUPPRESS} if after_command else {}
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--db", metavar="FILE",
                   help="database file (default: $XDG_DATA_HOME/grew/snapshots.db)", **extra)
    p.add_argument("--json", action="store_true", help="machine-readable output", **extra)
    p.add_argument("--no-color", action="store_true", help="disable colour", **extra)
    return p


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="grew",
        description="Track what is eating your disk, over time.",
        epilog="""examples:
  grew snap /home/me           take a snapshot now
  grew growth                  what changed since the last snapshot
  grew growth --since 7d       what changed in the last week
  grew top                     biggest directories right now
  grew list                    every snapshot taken
  grew prune --keep 10         drop old snapshots

--db, --json and --no-color go before or after the command.

tip: run `grew snap` from cron or a systemd timer, then ask `grew growth`
     whenever the disk fills up.""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[global_options(after_command=False)],
    )
    p.add_argument("--version", action="version", version=f"grew {__version__}")
    sub = p.add_subparsers(dest="cmd")
    common = [global_options(after_command=True)]

    # readonly/create tell main() how to open the database: commands that only
    # read must work on a read-only database and leave no file behind.
    s = sub.add_parser("snap", help="record directory sizes now", parents=common)
    s.add_argument("path", nargs="?", default=".",
                   help="directory to scan (default: the current directory)")
    s.add_argument("--min-size", type=parse_size, default="1M",
                   help="ignore directories below this (default 1M)")
    s.add_argument("--depth", type=positive_int, help="only record directories this deep")
    s.add_argument("--apparent", action="store_true",
                   help="use file size rather than allocated blocks")
    s.add_argument("--cross-filesystem", action="store_true",
                   help="descend into other mounts")
    s.add_argument("--exclude", action="append", default=[], metavar="PATH",
                   help="skip this path; repeatable, relative to the current directory")
    s.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    s.set_defaults(func=cmd_snap, readonly=False, create=True)

    g = sub.add_parser("growth", help="what changed between snapshots", parents=common)
    g.add_argument("path", nargs="?",
                   help="directory to compare (default: the one snapshotted last)")
    g.add_argument("--since", type=parse_duration, metavar="7d",
                   help="compare against this long ago")
    g.add_argument("--from", dest="from_id", type=int, metavar="ID",
                   help="compare this snapshot (an id from `grew list`) ...")
    g.add_argument("--to", dest="to_id", type=int, metavar="ID", help="... with this one")
    g.add_argument("-n", "--top", type=positive_int, default=20,
                   help="show at most this many directories (default 20)")
    g.add_argument("--min-size", type=parse_size, default="1M",
                   help="ignore changes smaller than this (default 1M)")
    g.add_argument("--all", action="store_true",
                   help="show parent directories too, not just the culprit")
    g.add_argument("--shrink", action="store_true", help="include directories that got smaller")
    g.set_defaults(func=cmd_growth, readonly=True, create=False)

    t = sub.add_parser("top", help="biggest directories in the latest snapshot",
                       parents=common)
    t.add_argument("path", nargs="?",
                   help="directory to show (default: the one snapshotted last)")
    t.add_argument("-n", "--top", type=positive_int, default=20,
                   help="show at most this many directories (default 20)")
    t.set_defaults(func=cmd_top, readonly=True, create=False)

    l = sub.add_parser("list", help="list snapshots", parents=common)
    l.add_argument("path", nargs="?", help="only list snapshots of this directory")
    l.set_defaults(func=cmd_list, readonly=True, create=False)

    pr = sub.add_parser("prune", help="delete old snapshots", parents=common)
    pr.add_argument("path", nargs="?", help="only prune snapshots of this directory")
    pr.add_argument("--keep", type=positive_int, default=20,
                    help="keep the newest N snapshots of each directory (default 20; 0 removes all)")
    pr.add_argument("-q", "--quiet", action="store_true",
                    help="print nothing on success (for cron)")
    pr.set_defaults(func=cmd_prune, readonly=False, create=False)

    return p


def is_tty(stream) -> bool:
    try:
        return stream.isatty()
    except (AttributeError, ValueError):      # closed, or no stdout at all
        return False


def silence(stream) -> None:
    """Point a stream at /dev/null so the flush at exit cannot fail noisily.

    After a failed write the text layer keeps its buffer and tries again when
    the interpreter exits; on a full disk that second failure turns the exit
    status into 120.
    """
    try:
        fd = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(fd, stream.fileno())
        finally:
            os.close(fd)
    except (OSError, ValueError, AttributeError):
        pass


def silence_stdout() -> None:
    silence(sys.stdout)


def main(argv: list[str] | None = None) -> int:
    # Undecodable filenames reach us as surrogates; strict UTF-8 output would
    # raise on them, so write them back out as the bytes they came from.
    for stream in (sys.stdout, sys.stderr):
        try:
            # Only UTF-8 can carry the raw bytes back out; any other encoding
            # would still raise on characters it lacks, so those are escaped.
            utf8 = codecs.lookup(stream.encoding).name == "utf-8"
            stream.reconfigure(errors="surrogateescape" if utf8 else "backslashreplace")
        except (AttributeError, ValueError, LookupError, TypeError):
            pass

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0

    use_colour = (
        not args.no_color
        and not os.environ.get("NO_COLOR")
        and is_tty(sys.stdout)
    )
    pal = Palette(use_colour)
    db = None
    try:
        db = connect(args.db, readonly=args.readonly, create=args.create)
        status = args.func(args, db, pal)
        if sys.stdout is not None:  # None when started with stdout closed
            sys.stdout.flush()      # surface a write error here, not at interpreter exit
        return status
    except BrokenPipeError:
        silence_stdout()
        return 0
    except KeyboardInterrupt:
        try:
            note("\ninterrupted")
        except KeyboardInterrupt:
            pass                # a second Ctrl-C while saying so: still just "interrupted"
        return 130
    except sqlite3.Error as exc:
        # connect() has its own handling; this is a failure while working, such
        # as a lock that outlasted the timeout or a disk that filled up mid-write.
        raise db_failure(db_path(args.db), exc, "read" if args.readonly else "write")
    except OSError as exc:
        silence_stdout()
        raise SystemExit(f"grew: i/o error: {exc}\n"
                         "      check the path, its permissions and free space, then try again")
    except UnicodeError as exc:
        raise SystemExit(f"grew: cannot encode some text for output: {exc}\n"
                         "      use a UTF-8 locale, or set PYTHONIOENCODING=utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        # sqlite will store any type in any column, so a database edited by hand
        # or by another tool can hold a string where a number belongs.
        quoted = safe(shlex.quote(db_path(args.db)))
        raise SystemExit(f"grew: unexpected data in database {safe(db_path(args.db))}: "
                         f"{type(exc).__name__}: {exc}\n"
                         f"      it may have been edited by another tool. move it aside "
                         f"(mv {quoted} {quoted}.bad)\n"
                         "      or pass --db FILE for a new one. grew never deletes it for you.")
    finally:
        if db is not None:
            try:
                db.close()
            except sqlite3.Error:
                pass


def entry() -> int:
    """main() for the command line: an error message must never be a second error.

    With stderr full or closed, the interpreter's own printing of a SystemExit
    message fails and the exit status becomes 120. Report the failure as 1.
    A Ctrl-C that arrives while main() is already handling one (or while it
    cleans up) is the same thing as the first: the shell's 130, not a traceback.
    """
    try:
        return main()
    except KeyboardInterrupt:
        return 130
    except SystemExit as exc:
        if not isinstance(exc.code, str):
            raise
        try:
            # Whatever put a path into the message, nothing in it may drive the
            # terminal (newlines and tabs are the message's own layout).
            sys.stderr.write(safe(exc.code, layout=True) + "\n")
            sys.stderr.flush()
        except (OSError, ValueError, AttributeError):
            silence(sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(entry())
