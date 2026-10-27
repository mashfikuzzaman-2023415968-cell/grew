#!/usr/bin/env python3
"""Adversarial tests for grew.

Every class here corresponds to a bug that was actually found by probing the
tool, or to an invariant that must not quietly break. Run with:

    python3 -m unittest -v test_hardening
"""

import argparse
import contextlib
import errno
import importlib.machinery
import importlib.util
import io
import json
import os
import random
import re
import shlex
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
GREW = os.path.join(HERE, "grew.py")

_spec = importlib.util.spec_from_loader(
    "grewmod", importlib.machinery.SourceFileLoader("grewmod", GREW))
g = importlib.util.module_from_spec(_spec)
sys.modules["grewmod"] = g
_spec.loader.exec_module(g)


def write(path, size_bytes=0):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(b"\0" * size_bytes)


def du_environment():
    """BLOCKSIZE=512, and without the variables that outrank it on GNU du."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("BLOCKSIZE", "BLOCK_SIZE", "DU_BLOCK_SIZE", "POSIXLY_CORRECT")}
    env["BLOCKSIZE"] = "512"
    return env


def du_command(path, one_fs=True):
    """Only options that GNU and BSD du share: -s, and -x for one filesystem."""
    return ["du", "-s"] + (["-x"] if one_fs else []) + [path]


def du_run(path, one_fs=True):
    """Ground truth: (bytes, exit status) from du.

    grew stays on one filesystem by default, as du -x does. --block-size=1 is
    GNU only and BSD du (macOS) rejects it; BLOCKSIZE=512 is honoured by both,
    so ask for 512-byte blocks and multiply. TestDuHelpers pins this with a du
    that behaves like BSD's.
    """
    out = subprocess.run(du_command(path, one_fs), capture_output=True, text=True,
                         env=du_environment(), errors="surrogateescape")
    return int(out.stdout.split()[0]) * 512, out.returncode


def du_bytes(path, one_fs=True):
    return du_run(path, one_fs)[0]


def apparent_bytes(path):
    """What du --apparent-size reports: file and symlink sizes, never directories.

    A directory's st_size is a filesystem artefact (4096 on ext4, 40 + 20 per
    entry on tmpfs), so --apparent leaves it out. Hardlinks count once and
    symlinks are not followed.
    """
    total, seen = 0, set()
    for folder, dirs, files in os.walk(path):
        links = [d for d in dirs if os.path.islink(os.path.join(folder, d))]
        for name in files + links:
            st = os.lstat(os.path.join(folder, name))
            if st.st_nlink > 1:
                if (st.st_dev, st.st_ino) in seen:
                    continue
                seen.add((st.st_dev, st.st_ino))
            total += st.st_size
    return total


def write_sparse(path, size_bytes):
    """A file whose apparent size is size_bytes, without writing it all out."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.truncate(size_bytes)


ANSI = re.compile(r"\x1b\[[0-9;]*m")


def run_main(*argv):
    """Run grew's main() in this process and capture what a user would see.

    Same parser, same code, no interpreter start-up: about a tenth of the cost
    of a subprocess. A traceback escaping main() would fail the test with the
    exception itself. Tests about process-level behaviour (exit status, real
    pipes, signals, the environment) still use subprocesses.
    """
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = g.main(list(argv))
        except SystemExit as exc:
            if exc.code is None:
                code = 0
            elif isinstance(exc.code, int):
                code = exc.code
            else:
                print(exc.code, file=sys.stderr)
                code = 1
    return subprocess.CompletedProcess(list(argv), code, out.getvalue(), err.getvalue())


class Base(unittest.TestCase):
    use_proc = False      # classes about real stdout/stderr behaviour set this

    def setUp(self):
        self.made_read_only = []      # (path, mode) to restore before cleaning up
        self.root = tempfile.mkdtemp(prefix="grewhard-")
        self.db = os.path.join(self.root, "db.sqlite")
        self.tree = os.path.join(self.root, "tree")
        os.makedirs(self.tree)
        # A regression that ignores --db would otherwise write into the
        # developer's real ~/.local/share/grew. Point both at the temp root;
        # nothing is created there unless grew really writes to it.
        sandbox = mock.patch.dict(os.environ, {
            "HOME": os.path.join(self.root, "home-sandbox"),
            "XDG_DATA_HOME": os.path.join(self.root, "xdg-sandbox")})
        sandbox.start()
        self.addCleanup(sandbox.stop)

    def tearDown(self):
        # A read-only directory cannot be emptied, so undo those first.
        for path, mode in reversed(self.made_read_only):
            try:
                os.chmod(path, mode)
            except OSError:
                pass
        # shutil.rmtree recurses, so it cannot delete the deep trees these
        # tests build. rm(1) is iterative.
        try:
            shutil.rmtree(self.root, ignore_errors=True)
        except RecursionError:
            pass
        if os.path.exists(self.root):
            subprocess.run(["rm", "-rf", self.root], check=False)

    def cli(self, *args, expect_ok=True, proc=None, env=None):
        """Run grew against self.db, in-process unless a real process is wanted."""
        if proc is None:
            proc = self.use_proc or env is not None
        if proc:
            # Output can legitimately contain undecodable filename bytes.
            result = subprocess.run([sys.executable, GREW, "--db", self.db, *args],
                                    capture_output=True, text=True, timeout=120,
                                    errors="surrogateescape", env=env)
        else:
            result = run_main("--db", self.db, *args)
        if expect_ok:
            self.assertEqual(result.returncode, 0,
                             f"exit {result.returncode}\nstdout: {result.stdout}"
                             f"\nstderr: {result.stderr}")
        return result

    def with_env(self, *args, env, expect_ok=True):
        """In-process, like cli() but without --db and with environment overrides."""
        with mock.patch.dict(os.environ, env):
            result = run_main(*args)
        if expect_ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def real(self, *args, env=None, expect_ok=True):
        """Always a real process, without --db (for the default database path)."""
        result = subprocess.run([sys.executable, GREW, *args], capture_output=True,
                                text=True, timeout=120, errors="surrogateescape",
                                env=env)
        if expect_ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def no_traceback(self, result):
        self.assertNotIn("Traceback", result.stderr or "")
        self.assertNotIn("Traceback", result.stdout or "")


# --------------------------------------------------------------------------- #
# regression: deep trees used to raise RecursionError
# --------------------------------------------------------------------------- #

class TestDeepTrees(Base):
    def _build(self, depth):
        cur = self.tree
        for _ in range(depth):
            cur = os.path.join(cur, "d")
            os.mkdir(cur)
        write(os.path.join(cur, "leaf.bin"), 4096)
        return cur

    def test_deeper_than_python_recursion_limit(self):
        """A 1,200-level tree used to blow the stack and lose the whole scan."""
        limit = sys.getrecursionlimit()
        self._build(limit + 200)
        res = g.scan(self.tree, apparent=True, min_size=0)
        self.assertGreaterEqual(res.files, 1)
        self.assertGreater(res.total, 0)

    def test_deep_tree_via_cli(self):
        self._build(1200)
        proc = self.cli("snap", self.tree, "-q", "--min-size", "1", proc=True)
        self.assertNotIn("Traceback", proc.stderr)

    def test_deep_tree_under_a_low_descriptor_limit(self):
        """Holding one open dir handle per level silently undercounted deep trees.

        Root usually has a high RLIMIT_NOFILE, so this only showed up when the
        suite was run as an ordinary user with the default limit of 1024.
        """
        depth = 600
        self._build(depth)
        script = (
            "import resource, sys, importlib.util, importlib.machinery\n"
            # Never raise the hard limit (not allowed): a sandbox that starts us
            # with less than 128 gets that lower figure instead.
            "hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]\n"
            "n = 128 if hard == resource.RLIM_INFINITY or hard > 128 else hard\n"
            "resource.setrlimit(resource.RLIMIT_NOFILE, (n, n))\n"
            f"spec = importlib.util.spec_from_loader('g', importlib.machinery.SourceFileLoader('g', {GREW!r}))\n"
            "g = importlib.util.module_from_spec(spec); sys.modules['g'] = g\n"
            "spec.loader.exec_module(g)\n"
            f"r = g.scan({self.tree!r}, min_size=0)\n"
            "print(r.files, r.errors)\n"
        )
        proc = subprocess.run([sys.executable, "-c", script],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        files, errors = (int(x) for x in proc.stdout.split())
        self.assertEqual(files, 1, "deep tree lost its file under a low fd limit")
        self.assertEqual(errors, 0, "deep tree reported errors under a low fd limit")

    def test_scan_does_not_leak_descriptors(self):
        """Repeated scans must not accumulate open handles."""
        for i in range(20):
            write(os.path.join(self.tree, f"d{i}", "f.bin"), 1024)
        fd_dir = "/proc/self/fd"
        if not os.path.isdir(fd_dir):
            self.skipTest("no /proc")
        before = len(os.listdir(fd_dir))
        for _ in range(25):
            g.scan(self.tree, min_size=0)
        after = len(os.listdir(fd_dir))
        self.assertLessEqual(after - before, 2, "descriptors leaked across scans")

    def test_deep_tree_matches_du(self):
        self._build(400)
        res = g.scan(self.tree, apparent=False, min_size=0)
        self.assertEqual(res.total, du_bytes(self.tree))


# --------------------------------------------------------------------------- #
# regression: blame() was O(n^2)
# --------------------------------------------------------------------------- #

class TestBlamePerformance(unittest.TestCase):
    def _changes(self, n):
        random.seed(7)
        before, after = {}, {}
        for i in range(n):
            depth = random.randint(1, 5)
            p = "/root/" + "/".join("d%d" % random.randint(0, 30)
                                    for _ in range(depth)) + "/leaf%d" % i
            before[p] = random.randint(0, 10 ** 6)
            after[p] = before[p] + random.randint(0, 10 ** 6)
        return g.diff(before, after)

    def test_scales_to_many_changes(self):
        """8,000 changed directories took 4.3s before; it must stay interactive."""
        changes = self._changes(8000)
        start = time.perf_counter()
        g.blame(changes)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 1.0, f"blame took {elapsed:.2f}s for 8000 changes")

    def test_growth_is_not_quadratic(self):
        """Doubling the input must not quadruple the time."""
        small = self._changes(2000)
        large = self._changes(8000)   # 4x the entries

        def timed(ch):
            # The fastest of several runs: a one-off stall (a loaded CI runner
            # descheduling the process) inflates a single sample, never the best.
            best = float("inf")
            for _ in range(5):
                start = time.perf_counter()
                g.blame(ch)
                best = min(best, time.perf_counter() - start)
            return best

        timed(small)  # warm up
        t_small = max(timed(small), 1e-4)
        t_large = timed(large)
        self.assertLess(t_large / t_small, 10,
                        "4x input should not cost ~16x time")


# --------------------------------------------------------------------------- #
# blame correctness, including the cases the fast version must preserve
# --------------------------------------------------------------------------- #

class TestBlameCorrectness(unittest.TestCase):
    def kept(self, before, after, **kw):
        return sorted(c.path for c in g.blame(g.diff(before, after), **kw))

    def test_single_culprit_chain(self):
        self.assertEqual(
            self.kept({"/p": 0, "/p/a": 0, "/p/a/b": 0},
                      {"/p": 900, "/p/a": 900, "/p/a/b": 900}),
            ["/p/a/b"])

    def test_spread_growth_keeps_parent(self):
        kept = self.kept({"/p": 0, "/p/a": 0, "/p/b": 0},
                         {"/p": 1000, "/p/a": 500, "/p/b": 500})
        self.assertIn("/p", kept)

    def test_sibling_prefix_is_not_a_child(self):
        """/pow must never be treated as a descendant of /p."""
        self.assertEqual(
            self.kept({"/p": 0, "/pow": 0}, {"/p": 1000, "/pow": 1000}),
            ["/p", "/pow"])

    def test_similar_prefixes_at_depth(self):
        self.assertEqual(
            self.kept({"/a/bc": 0, "/a/bcd": 0}, {"/a/bc": 500, "/a/bcd": 500}),
            ["/a/bc", "/a/bcd"])

    def test_opposite_directions_not_suppressed(self):
        kept = self.kept({"/p": 0, "/p/a": 1000}, {"/p": 1000, "/p/a": 0})
        self.assertIn("/p", kept)

    def test_skip_level_ancestor_is_suppressed(self):
        """Suppression must work even when an intermediate dir is absent."""
        self.assertEqual(
            self.kept({"/p": 0, "/p/a/b/c": 0}, {"/p": 900, "/p/a/b/c": 900}),
            ["/p/a/b/c"])

    def test_explain_threshold_is_respected(self):
        # child is 80% of parent: below the default 0.9, so the parent survives
        kept = self.kept({"/p": 0, "/p/a": 0}, {"/p": 1000, "/p/a": 800})
        self.assertIn("/p", kept)
        # ...but not at an explicit lower threshold
        kept = self.kept({"/p": 0, "/p/a": 0}, {"/p": 1000, "/p/a": 800}, explain=0.5)
        self.assertNotIn("/p", kept)

    def test_relative_paths_terminate(self):
        self.assertEqual(self.kept({"a/b": 0}, {"a/b": 100}), ["a/b"])

    def test_root_path_terminates(self):
        kept = self.kept({"/": 0, "/x": 0}, {"/": 500, "/x": 500})
        self.assertEqual(kept, ["/x"])


# --------------------------------------------------------------------------- #
# regression: growth compared snapshots of unrelated directories
# --------------------------------------------------------------------------- #

class TestRootScoping(Base):
    def setUp(self):
        super().setUp()
        self.other = os.path.join(self.root, "other")
        os.makedirs(self.other)

    def test_growth_does_not_mix_roots(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent")
        self.cli("snap", self.tree, "-q", "--apparent")
        write(os.path.join(self.other, "b.bin"), 8 * 1048576)
        self.cli("snap", self.other, "-q", "--apparent")

        # The newest snapshot is `other`, which has only one snapshot.
        proc = self.cli("growth", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(self.other, proc.stderr)

    def test_growth_with_explicit_path_is_scoped(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        before = apparent_bytes(self.tree)
        self.cli("snap", self.tree, "-q", "--apparent")
        write(os.path.join(self.tree, "b.bin"), 1048576)
        after = apparent_bytes(self.tree)
        self.cli("snap", self.tree, "-q", "--apparent")
        self.cli("snap", self.other, "-q", "--apparent")

        out = self.cli("--json", "growth", self.tree, "--min-size", "1").stdout
        data = json.loads(out)
        # The oracle is what the filesystem reports for the files, the same on
        # ext4, tmpfs and btrfs, and the other root's snapshot must not leak in.
        self.assertEqual(data["net"], after - before)
        self.assertEqual(data["net"], 1048576)
        self.assertEqual(data["root"], self.tree)

    def test_from_to_across_roots_is_rejected(self):
        self.cli("snap", self.tree, "-q")
        self.cli("snap", self.other, "-q")
        proc = self.cli("growth", "--from", "1", "--to", "2", expect_ok=False)
        self.assertIn("different directories", proc.stderr)


# --------------------------------------------------------------------------- #
# argument and input validation
# --------------------------------------------------------------------------- #

class TestValidation(Base):
    def test_from_requires_to(self):
        self.cli("snap", self.tree, "-q")
        self.cli("snap", self.tree, "-q")
        proc = self.cli("growth", "--from", "1", expect_ok=False)
        self.assertIn("must be given together", proc.stderr)

    def test_unknown_snapshot_id(self):
        self.cli("snap", self.tree, "-q")
        proc = self.cli("growth", "--from", "99", "--to", "100", expect_ok=False)
        self.assertIn("no snapshot", proc.stderr)

    def test_negative_top_rejected(self):
        proc = self.cli("top", "-n", "-5", expect_ok=False)
        self.assertIn("negative", proc.stderr)

    def test_bad_size_rejected(self):
        proc = self.cli("snap", self.tree, "--min-size", "banana", expect_ok=False)
        self.assertIn("size", proc.stderr.lower())

    def test_bad_duration_rejected(self):
        self.cli("snap", self.tree, "-q")
        self.cli("snap", self.tree, "-q")
        proc = self.cli("growth", "--since", "7y", expect_ok=False)
        self.assertIn("duration", proc.stderr.lower())

    def test_corrupt_database_is_explained(self):
        with open(self.db, "w") as f:
            f.write("definitely not sqlite")
        proc = self.cli("list", expect_ok=False, proc=True)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("corrupt", proc.stderr)

    def test_db_pointing_at_directory(self):
        proc = subprocess.run([sys.executable, GREW, "--db", self.root, "list"],
                              capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("directory", proc.stderr)

    def test_snapshot_of_missing_path(self):
        proc = self.cli("snap", os.path.join(self.tree, "ghost"), expect_ok=False)
        self.assertIn("not a directory", proc.stderr)


# --------------------------------------------------------------------------- #
# filesystem oddities
# --------------------------------------------------------------------------- #

class TestFilesystemOddities(Base):
    def test_hostile_filenames(self):
        names = ["with space", "with'quote", 'with"dquote', "üñïçødé",
                 "-dashed", "new\nline", "semi;colon", "star*glob"]
        for n in names:
            try:
                write(os.path.join(self.tree, n, "f.bin"), 4096)
            except (OSError, UnicodeEncodeError):    # a name this filesystem cannot hold
                continue
        res = g.scan(self.tree, apparent=True, min_size=0)
        for n in names:
            p = os.path.join(self.tree, n)
            if os.path.isdir(p):
                self.assertIn(p, res.sizes, f"lost directory named {n!r}")

    def test_hostile_filenames_survive_the_database(self):
        try:
            write(os.path.join(self.tree, "üñï code", "f.bin"), 1048576)
        except UnicodeEncodeError:
            self.skipTest("the filesystem encoding cannot hold non-ASCII names")
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        data = json.loads(self.cli("--json", "top").stdout)
        self.assertTrue(any("üñï code" in e["path"] for e in data))

    def test_fifo_and_socket_do_not_break_scan(self):
        os.mkfifo(os.path.join(self.tree, "pipe"))
        sock = socket.socket(socket.AF_UNIX)
        try:
            # sun_path holds about 104 bytes, and macOS temp directories are
            # longer than that, so bind by a relative name from inside the tree.
            here = os.getcwd()
            os.chdir(self.tree)
            try:
                sock.bind("sock")
            finally:
                os.chdir(here)
            res = g.scan(self.tree, apparent=True, min_size=0)
            self.assertEqual(res.errors, 0)
            self.assertIn(self.tree, res.sizes)
        finally:
            sock.close()

    def test_symlink_inode_is_counted_like_du(self):
        """du bills a symlink's own inode; skipping them undercounted /etc by 5.8%."""
        target = os.path.join(self.tree, "target.bin")
        write(target, 4096)
        linkdir = os.path.join(self.tree, "links")
        os.makedirs(linkdir)
        for i in range(300):
            os.symlink(target, os.path.join(linkdir, f"link{i}"))
        res = g.scan(self.tree, apparent=False, min_size=0)
        self.assertEqual(res.total, du_bytes(self.tree),
                         "symlink inodes must be counted without being followed")

    def test_symlink_target_is_not_followed(self):
        """Counting the inode must not mean counting the target twice."""
        big = os.path.join(self.tree, "real", "big.bin")
        write(big, 8 * 1048576)
        os.symlink(os.path.join(self.tree, "real"), os.path.join(self.tree, "alias"))
        res = g.scan(self.tree, apparent=False, min_size=0)
        self.assertEqual(res.total, du_bytes(self.tree))
        self.assertLess(res.total, 16 * 1048576, "target counted twice")

    def test_broken_symlink(self):
        os.symlink(os.path.join(self.tree, "nothing"), os.path.join(self.tree, "dangling"))
        res = g.scan(self.tree, apparent=True, min_size=0)
        self.assertEqual(res.errors, 0)

    def test_symlink_to_parent_does_not_loop(self):
        inner = os.path.join(self.tree, "inner")
        os.makedirs(inner)
        os.symlink(self.tree, os.path.join(inner, "up"))
        res = g.scan(self.tree, apparent=True, min_size=0)  # must terminate
        self.assertIn(self.tree, res.sizes)

    def test_sparse_file_counts_allocated_not_apparent(self):
        p = os.path.join(self.tree, "sparse.bin")
        with open(p, "wb") as f:
            f.seek(64 * 1048576)
            f.write(b"x")
        allocated = g.scan(self.tree, apparent=False, min_size=0).total
        apparent = g.scan(self.tree, apparent=True, min_size=0).total
        self.assertLess(allocated, apparent,
                        "a sparse file should occupy less than its apparent size")
        self.assertEqual(allocated, du_bytes(self.tree))

    def test_empty_directories_everywhere(self):
        for i in range(50):
            os.makedirs(os.path.join(self.tree, f"empty{i}", "deeper"))
        res = g.scan(self.tree, apparent=True, min_size=0)
        self.assertEqual(res.files, 0)

    def test_many_files_in_one_directory(self):
        for i in range(2000):
            write(os.path.join(self.tree, "flat", f"f{i}.bin"), 128)
        res = g.scan(self.tree, apparent=False, min_size=0)
        self.assertEqual(res.files, 2000)
        self.assertEqual(res.total, du_bytes(self.tree))


# --------------------------------------------------------------------------- #
# invariants that must hold for any tree
# --------------------------------------------------------------------------- #

class TestRealFilesystems(unittest.TestCase):
    """Parity against du on real system trees, found at run time.

    It used to scan all of /usr, /home, /var and /opt, which took minutes,
    skipped everything the moment one tree had a single unreadable file (so on
    an ordinary user's machine it barely checked anything), and raced with live
    changes under /var and /home. Now: small, quiet trees that this user can
    read completely, each in its own subTest so an unreadable one only drops
    itself, with one retry to absorb a live change, inside a time budget.
    """

    BUDGET = 20.0       # seconds of wall clock to spend looking for trees
    WANT = 3            # trees to check before stopping

    @staticmethod
    def quiet_trees():
        stdlib = os.path.dirname(os.__file__)     # present everywhere, rarely changes
        candidates = [stdlib, "/usr/share/zoneinfo", "/usr/share/man", "/usr/include",
                      "/usr/lib/python3", "/usr/share/locale", "/etc/ssl",
                      "/usr/share/doc", "/usr/share/terminfo", "/etc", "/opt", "/usr/local"]
        seen = []
        for path in candidates:
            if os.path.isdir(path) and os.access(path, os.R_OK | os.X_OK) \
                    and path not in seen:
                seen.append(path)
        return seen

    @staticmethod
    def nested_mount_parents():
        """Directories that contain another filesystem's mount point, deepest first.

        Read from the mount table, keeping only real disk filesystems outside
        the pseudo-filesystem directories grew skips. /snap/NAME holding the
        read-only squashfs mounts of its revisions is the common case on
        Linux, and nothing writes to those.
        """
        real = {"squashfs", "erofs", "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs",
                "vfat", "iso9660"}
        skipped = tuple(d + "/" for d in g.SKIP_DIRS)
        parents = set()
        try:
            with open("/proc/self/mountinfo") as f:
                lines = f.read().splitlines()
        except OSError:
            return []
        for line in lines:
            fields = line.split()
            if "-" not in fields:
                continue
            mount, fstype = fields[4], fields[fields.index("-") + 1]
            if fstype not in real or "\\" in mount or mount in g.SKIP_DIRS \
                    or mount.startswith(skipped):
                continue
            parent = os.path.dirname(mount)
            if parent in ("", "/"):
                continue                     # the whole root filesystem is too big
            try:
                if os.stat(parent).st_dev == os.stat(mount).st_dev:
                    continue
            except OSError:
                continue
            parents.add(parent)
        return sorted(parents, key=lambda p: (-p.count("/"), p))

    @staticmethod
    def parity(target, one_fs):
        """(grew, du) for target, or None when it cannot be compared fairly.

        A tree with unreadable entries is not comparable: grew counts them as
        errors and du exits non-zero. A second attempt absorbs the odd file
        that changed between the two measurements.
        """
        for _ in range(2):
            res = g.scan(target, apparent=False, min_size=0, one_fs=one_fs)
            oracle, status = du_run(target, one_fs=one_fs)
            if res.errors or status != 0:
                return None
            if res.total == oracle:
                break
        return res.total, oracle

    def test_matches_du_x_on_real_trees(self):
        start, checked, tried = time.monotonic(), 0, []
        for target in self.quiet_trees():
            if checked >= self.WANT or time.monotonic() - start > self.BUDGET:
                break
            with self.subTest(target=target):
                tried.append(target)
                pair = self.parity(target, one_fs=True)
                if pair is None:
                    continue                 # unreadable here: try the next one
                checked += 1
                self.assertEqual(pair[0], pair[1], f"grew vs du -x on {target}")
        if not checked:
            self.skipTest(f"no completely readable real tree among {tried}")

    def test_cross_filesystem_matches_plain_du(self):
        """With --cross-filesystem, grew should agree with du's default.

        And without it, grew should agree with du -x, which leaves the nested
        mount out: the same tree must give two different, both correct, totals.
        """
        start, checked = time.monotonic(), 0
        for target in self.nested_mount_parents():
            if checked >= 2 or time.monotonic() - start > self.BUDGET:
                break
            plain, status_plain = du_run(target, one_fs=False)
            scoped, status_scoped = du_run(target, one_fs=True)
            if status_plain or status_scoped or plain == scoped:
                continue                     # unreadable, or the mount is empty
            with self.subTest(target=target):
                across = self.parity(target, one_fs=False)
                within = self.parity(target, one_fs=True)
                if across is None or within is None:
                    continue
                checked += 1
                self.assertEqual(across[0], across[1], f"grew vs plain du on {target}")
                self.assertEqual(within[0], within[1], f"grew vs du -x on {target}")
                self.assertGreater(across[0], within[0],
                                   "the nested mount contributed nothing")
        if not checked:
            self.skipTest("no completely readable directory with a nested mount point")


class TestInvariants(Base):
    def random_tree(self, seed, dirs=40, files=120):
        rnd = random.Random(seed)
        paths = [self.tree]
        for _ in range(dirs):
            parent = rnd.choice(paths)
            p = os.path.join(parent, "d%d" % rnd.randint(0, 9999))
            os.makedirs(p, exist_ok=True)
            paths.append(p)
        for i in range(files):
            write(os.path.join(rnd.choice(paths), "f%d.bin" % i), rnd.randint(0, 40000))
        return paths

    def test_fuzz_parent_always_at_least_child(self):
        """Cumulative sizes mean a parent can never be smaller than a child."""
        for seed in range(6):
            with self.subTest(seed=seed):
                shutil.rmtree(self.tree, ignore_errors=True)
                os.makedirs(self.tree)
                self.random_tree(seed)
                res = g.scan(self.tree, apparent=False, min_size=0)
                for path, size in res.sizes.items():
                    parent = os.path.dirname(path)
                    if parent in res.sizes and parent != path:
                        self.assertGreaterEqual(
                            res.sizes[parent], size,
                            f"{parent} smaller than its child {path}")

    def test_fuzz_total_matches_du(self):
        for seed in range(6):
            with self.subTest(seed=seed):
                shutil.rmtree(self.tree, ignore_errors=True)
                os.makedirs(self.tree)
                self.random_tree(seed)
                res = g.scan(self.tree, apparent=False, min_size=0)
                self.assertEqual(res.total, du_bytes(self.tree))

    def test_fuzz_root_entry_equals_total(self):
        for seed in range(4):
            with self.subTest(seed=seed):
                shutil.rmtree(self.tree, ignore_errors=True)
                os.makedirs(self.tree)
                self.random_tree(seed)
                res = g.scan(self.tree, apparent=True, min_size=0)
                self.assertEqual(res.sizes[self.tree], res.total)

    def test_scan_is_deterministic(self):
        self.random_tree(99)
        a = g.scan(self.tree, apparent=False, min_size=0)
        b = g.scan(self.tree, apparent=False, min_size=0)
        self.assertEqual(a.sizes, b.sizes)
        self.assertEqual(a.total, b.total)

    def test_min_size_never_changes_the_total(self):
        self.random_tree(5)
        full = g.scan(self.tree, apparent=False, min_size=0)
        pruned = g.scan(self.tree, apparent=False, min_size=1048576)
        self.assertEqual(full.total, pruned.total)
        self.assertLessEqual(len(pruned.sizes), len(full.sizes))

    def test_identical_snapshots_show_no_growth(self):
        self.random_tree(3)
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        data = json.loads(self.cli("--json", "growth", "--min-size", "1").stdout)
        self.assertEqual(data["net"], 0)
        self.assertEqual(data["changes"], [])

    def test_blame_never_invents_paths(self):
        self.random_tree(11)
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        self.random_tree(12)
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        data = json.loads(self.cli("--json", "growth", "--min-size", "1").stdout)
        for change in data["changes"]:
            self.assertTrue(change["path"].startswith(self.tree))


# --------------------------------------------------------------------------- #
# options behave as documented
# --------------------------------------------------------------------------- #

class TestOptions(Base):
    def test_depth_limits_recorded_directories(self):
        write(os.path.join(self.tree, "a/b/c/deep.bin"), 4 * 1048576)
        res = g.scan(self.tree, apparent=True, min_size=0, max_depth=2)
        self.assertIn(os.path.join(self.tree, "a"), res.sizes)
        self.assertIn(os.path.join(self.tree, "a/b"), res.sizes)
        self.assertNotIn(os.path.join(self.tree, "a/b/c"), res.sizes)
        # The deep file still counts toward every recorded ancestor.
        self.assertGreaterEqual(res.sizes[os.path.join(self.tree, "a/b")], 4 * 1048576)

    def test_depth_does_not_change_the_total(self):
        write(os.path.join(self.tree, "a/b/c/deep.bin"), 4 * 1048576)
        shallow = g.scan(self.tree, apparent=True, min_size=0, max_depth=1).total
        full = g.scan(self.tree, apparent=True, min_size=0).total
        self.assertEqual(shallow, full)

    def test_since_falls_back_to_oldest(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent")
        write(os.path.join(self.tree, "b.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent")
        # Nothing is a year old, so it should use the oldest rather than fail.
        data = json.loads(self.cli("--json", "growth", "--since", "52w",
                                   "--min-size", "1").stdout)
        self.assertEqual(data["from"]["id"], 1)

    def test_shrink_hidden_by_default(self):
        write(os.path.join(self.tree, "big.bin"), 8 * 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        os.remove(os.path.join(self.tree, "big.bin"))
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")

        default = json.loads(self.cli("--json", "growth", "--min-size", "1").stdout)
        self.assertEqual(default["changes"], [])
        withshrink = json.loads(self.cli("--json", "growth", "--shrink",
                                         "--min-size", "1").stdout)
        self.assertTrue(any(c["delta"] < 0 for c in withshrink["changes"]))

    def test_exclude_is_honoured_via_cli(self):
        write(os.path.join(self.tree, "keep/f.bin"), 2 * 1048576)
        write(os.path.join(self.tree, "skip/f.bin"), 8 * 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1",
                 "--exclude", os.path.join(self.tree, "skip"))
        data = json.loads(self.cli("--json", "top").stdout)
        self.assertFalse(any("skip" in e["path"] for e in data))

    def test_prune_is_scoped_to_a_path(self):
        other = os.path.join(self.root, "other")
        os.makedirs(other)
        for _ in range(3):
            self.cli("snap", self.tree, "-q")
        for _ in range(3):
            self.cli("snap", other, "-q")
        self.cli("prune", self.tree, "--keep", "1")
        rows = json.loads(self.cli("--json", "list").stdout)
        tree_rows = [r for r in rows if r["root"] == self.tree]
        other_rows = [r for r in rows if r["root"] == other]
        self.assertEqual(len(tree_rows), 1)
        self.assertEqual(len(other_rows), 3, "pruning one root must not touch another")

    def test_apparent_flag_is_recorded(self):
        self.cli("snap", self.tree, "-q", "--apparent")
        rows = json.loads(self.cli("--json", "list").stdout)
        self.assertEqual(rows[-1]["apparent"], 1)


# --------------------------------------------------------------------------- #
# output contracts
# --------------------------------------------------------------------------- #

class TestOutput(Base):
    def test_every_command_emits_valid_json(self):
        write(os.path.join(self.tree, "a.bin"), 2 * 1048576)
        snap = json.loads(self.cli("--json", "snap", self.tree,
                                   "--apparent", "--min-size", "1").stdout)
        self.assertIn("id", snap)
        write(os.path.join(self.tree, "b.bin"), 2 * 1048576)
        self.cli("--json", "snap", self.tree, "--apparent", "--min-size", "1")

        for args in (["list"], ["top"], ["growth", "--min-size", "1"]):
            with self.subTest(args=args):
                json.loads(self.cli("--json", *args).stdout)

    def test_json_growth_schema(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        write(os.path.join(self.tree, "b.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        data = json.loads(self.cli("--json", "growth", "--min-size", "1").stdout)
        for key in ("from", "to", "net", "changes"):
            self.assertIn(key, data)
        for key in ("id", "ts", "total"):
            self.assertIn(key, data["from"])
        for change in data["changes"]:
            for key in ("path", "before", "after", "delta"):
                self.assertIn(key, change)
            self.assertEqual(change["delta"], change["after"] - change["before"])

    def test_no_ansi_when_piped(self):
        write(os.path.join(self.tree, "a.bin"), 2 * 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        write(os.path.join(self.tree, "b.bin"), 2 * 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        for args in (["growth", "--min-size", "1"], ["top"], ["list"]):
            with self.subTest(args=args):
                # A real pipe, so stdout genuinely is not a terminal.
                self.assertNotIn("\033[", self.cli(*args, proc=True).stdout)

    def test_no_color_env_is_respected(self):
        self.cli("snap", self.tree, "-q")
        env = dict(os.environ, NO_COLOR="1")
        proc = subprocess.run([sys.executable, GREW, "--db", self.db, "list"],
                              capture_output=True, text=True, env=env)
        self.assertNotIn("\033[", proc.stdout)

    def test_sigpipe_does_not_traceback(self):
        for i in range(30):
            write(os.path.join(self.tree, f"d{i}", "f.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        p1 = subprocess.Popen([sys.executable, GREW, "--db", self.db, "top", "-n", "100"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p2 = subprocess.Popen(["head", "-1"], stdin=p1.stdout,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p1.stdout.close()
        p2.communicate()
        _, err = p1.communicate()
        self.assertNotIn(b"Traceback", err)
        self.assertNotIn(b"BrokenPipe", err)

    def test_empty_database_messages_are_friendly(self):
        for args in (["list"], ["top"], ["growth"]):
            with self.subTest(args=args):
                proc = self.cli(*args, expect_ok=False)
                self.assertNotIn("Traceback", proc.stderr)

    def test_help_for_every_subcommand(self):
        for cmd in ("snap", "growth", "top", "list", "prune"):
            with self.subTest(cmd=cmd):
                proc = self.cli(cmd, "--help")
                self.assertIn("usage", proc.stdout.lower())


# --------------------------------------------------------------------------- #
# concurrency and persistence
# --------------------------------------------------------------------------- #

class TestConcurrency(Base):
    use_proc = True

    def test_parallel_snapshots_all_land(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        procs = [subprocess.Popen(
            [sys.executable, GREW, "--db", self.db, "snap", self.tree, "-q"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(10)]
        errors = []
        for p in procs:
            _, err = p.communicate(timeout=60)
            if p.returncode != 0:
                errors.append(err.decode())
        self.assertEqual(errors, [], "concurrent snapshots should not fail")
        rows = json.loads(self.cli("--json", "list").stdout)
        self.assertEqual(len(rows), 10)

    def test_read_during_write_is_safe(self):
        for i in range(200):
            write(os.path.join(self.tree, f"d{i}", "f.bin"), 4096)
        writer = subprocess.Popen(
            [sys.executable, GREW, "--db", self.db, "snap", self.tree, "-q", "--min-size", "1"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.cli("list")  # must not deadlock or error
        writer.communicate(timeout=60)
        self.assertEqual(writer.returncode, 0)


# --------------------------------------------------------------------------- #
# round two: bugs found by a second adversarial pass
# --------------------------------------------------------------------------- #

class TestUndecodableFilenames(Base):
    """Linux filenames are bytes. Undecodable ones used to crash the snapshot."""

    def _make(self):
        raw = os.path.join(os.fsencode(self.tree), b"bad\xff\xfename")
        os.makedirs(raw, exist_ok=True)
        with open(os.path.join(raw, b"f.bin"), "wb") as f:
            f.write(b"\0" * 2 * 1048576)
        return os.fsdecode(raw)

    def test_scan_handles_them(self):
        path = self._make()
        res = g.scan(self.tree, apparent=True, min_size=0)
        self.assertIn(path, res.sizes)

    def test_snapshot_stores_them(self):
        self._make()
        proc = self.cli("snap", self.tree, "-q", "--min-size", "1")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)

    def test_round_trips_through_the_database(self):
        path = self._make()
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        db = g.connect(self.db)
        try:
            snaps = g.snapshots_for(db, None)
            entries = g.load_entries(db, snaps[-1]["id"])
        finally:
            db.close()
        self.assertIn(path, entries, "path did not survive the round trip")

    def test_json_output_is_still_valid(self):
        self._make()
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        data = json.loads(self.cli("--json", "top", proc=True).stdout)
        self.assertTrue(data)

    def test_growth_reports_them(self):
        path = self._make()
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        with open(os.path.join(os.fsencode(path), b"more.bin"), "wb") as f:
            f.write(b"\0" * 3 * 1048576)
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        data = json.loads(self.cli("--json", "growth", "--min-size", "1").stdout)
        self.assertTrue(any(c["delta"] > 0 for c in data["changes"]))

    def test_printing_does_not_crash(self):
        self._make()
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        proc = self.cli("top", proc=True)        # a real stdout, which must take the bytes
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("bad", proc.stdout)


class TestMeasurementConsistency(Base):
    """Diffing an --apparent snapshot against an allocated one is meaningless."""

    def test_mixed_modes_are_refused(self):
        for i in range(40):
            write(os.path.join(self.tree, f"f{i}.txt"), 3)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        proc = self.cli("growth", "--min-size", "1", expect_ok=False)
        self.assertIn("measure size differently", proc.stderr)

    def test_matching_modes_are_allowed(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        data = json.loads(self.cli("--json", "growth", "--min-size", "1").stdout)
        self.assertEqual(data["net"], 0)

    def test_mixed_modes_rejected_via_from_to(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent")
        self.cli("snap", self.tree, "-q")
        proc = self.cli("growth", "--from", "1", "--to", "2", expect_ok=False)
        self.assertIn("measure size differently", proc.stderr)


class TestSchemaGuard(Base):
    use_proc = True

    def test_newer_schema_is_refused(self):
        self.cli("snap", self.tree, "-q")
        import sqlite3 as sq
        con = sq.connect(self.db)
        con.execute("UPDATE meta SET value='99' WHERE key='schema'")
        con.commit()
        con.close()
        proc = self.cli("list", expect_ok=False)
        self.assertIn("schema v99", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_current_schema_is_accepted(self):
        self.cli("snap", self.tree, "-q")
        self.cli("list")


class TestHumanBoundaries(unittest.TestCase):
    def test_never_prints_1024_of_a_unit(self):
        """Rounding used to produce "1024K" instead of promoting to 1.0M."""
        for n in range(1048500, 1048600):
            rendered = g.human(n)
            self.assertNotIn("1024", rendered, f"{n} rendered as {rendered}")

    def test_promotes_at_every_unit_boundary(self):
        for power in range(1, 6):
            just_under = 1024 ** (power + 1) - 1
            self.assertNotIn("1024", g.human(just_under))

    def test_negative_without_signed_keeps_its_sign(self):
        self.assertEqual(g.human(-1048576), "-1.0M")
        self.assertEqual(g.human(-512), "-512B")

    def test_signed_zero_is_neutral(self):
        self.assertEqual(g.human(0, signed=True).strip(), "0B")

    def test_monotonic(self):
        """Bigger inputs must never render as a smaller unit."""
        order = "BKMGTPE"
        last = -1
        for power in range(0, 7):
            unit = g.human(1024 ** power + 1)[-1]
            idx = order.index(unit)
            self.assertGreaterEqual(idx, last)
            last = idx


class TestLiveFilesystemRaces(Base):
    def test_directory_deleted_mid_scan(self):
        import threading
        for i in range(400):
            write(os.path.join(self.tree, f"d{i}", "f.bin"), 50000)

        def remover():
            time.sleep(0.002)
            for i in range(0, 400, 3):
                shutil.rmtree(os.path.join(self.tree, f"d{i}"), ignore_errors=True)

        th = threading.Thread(target=remover)
        th.start()
        try:
            res = g.scan(self.tree, apparent=False, min_size=0)
        finally:
            th.join()
        self.assertGreater(res.total, 0)

    def test_interrupted_snapshot_leaves_no_partial_rows(self):
        for i in range(400):
            write(os.path.join(self.tree, f"d{i}", "f.bin"), 20000)
        proc = subprocess.Popen(
            [sys.executable, GREW, "--db", self.db, "snap", self.tree, "--min-size", "1"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.03)
        proc.send_signal(2)  # SIGINT
        proc.communicate(timeout=30)

        import sqlite3 as sq
        if not os.path.exists(self.db):
            return  # killed before anything was written: also correct
        con = sq.connect(self.db)
        try:
            tables = {r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if "snapshots" not in tables:
                return
            snaps = con.execute("SELECT id FROM snapshots").fetchall()
            orphans = con.execute(
                "SELECT COUNT(*) FROM entries WHERE snap NOT IN "
                "(SELECT id FROM snapshots)").fetchone()[0]
        finally:
            con.close()
        self.assertEqual(orphans, 0, "entries without a parent snapshot")
        # Either the snapshot completed or nothing was written; never half.
        self.assertIn(len(snaps), (0, 1))



# --------------------------------------------------------------------------- #
# round three: failures must be explained, and explained correctly
# --------------------------------------------------------------------------- #

def digest(path):
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def made_read_only(testcase, *paths):
    """chmod paths read-only now; Base.tearDown makes them writable so rm -rf works."""
    for path in paths:
        mode = os.stat(path).st_mode & 0o777
        testcase.made_read_only.append((path, mode | 0o700))
        os.chmod(path, mode & ~0o222)


class TestDatabaseLocation(Base):
    """Where the database goes, and that reading never creates it (A1, B2)."""

    def setUp(self):
        super().setUp()
        self.blocker = os.path.join(self.root, "blocker")
        with open(self.blocker, "w") as f:
            f.write("a regular file where a directory is needed")

    def test_xdg_data_home_under_a_regular_file_gives_advice_not_a_traceback(self):
        env = dict(os.environ, XDG_DATA_HOME=self.blocker)
        proc = self.real("snap", self.tree, "-q", env=env, expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.no_traceback(proc)
        self.assertIn("cannot create database directory", proc.stderr)
        self.assertIn("XDG_DATA_HOME", proc.stderr)
        self.assertIn("--db", proc.stderr)

    def test_xdg_data_home_in_a_read_only_directory_gives_advice(self):
        if os.geteuid() == 0:
            self.skipTest("root can write anywhere")
        locked = os.path.join(self.root, "locked")
        os.makedirs(locked)
        made_read_only(self, locked)
        proc = self.with_env("snap", self.tree, "-q", env={"XDG_DATA_HOME": locked},
                             expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.no_traceback(proc)
        self.assertIn("XDG_DATA_HOME", proc.stderr)
        self.assertEqual(os.listdir(locked), [], "grew wrote into a read-only directory")

    def test_explicit_db_under_a_regular_file_names_the_db_option(self):
        proc = run_main("--db", os.path.join(self.blocker, "x.db"), "snap", self.tree)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("cannot create database directory", proc.stderr)
        self.assertIn("--db", proc.stderr)
        self.assertNotIn("XDG_DATA_HOME", proc.stderr)

    def test_unusable_default_location_does_not_stop_reading(self):
        proc = self.with_env("--json", "list", env={"XDG_DATA_HOME": self.blocker})
        self.assertEqual(json.loads(proc.stdout), [])

    def test_read_commands_on_a_missing_database_create_nothing(self):
        folder = os.path.join(self.root, "not", "yet")
        target = os.path.join(folder, "x.db")
        for args, status in ((["list"], 0), (["--json", "list"], 0), (["top"], 1),
                             (["growth"], 1), (["prune"], 0), (["--json", "prune"], 0)):
            with self.subTest(args=args):
                proc = run_main("--db", target, *args)
                self.assertEqual(proc.returncode, status, proc.stderr)
                self.assertFalse(os.path.exists(os.path.join(self.root, "not")),
                                 "a read-only command created the database directory")
        self.assertEqual(json.loads(run_main("--db", target, "--json", "list").stdout), [])

    def test_read_commands_with_the_default_path_create_nothing(self):
        xdg = os.path.join(self.root, "xdg")
        for args in (["list"], ["top"], ["growth"], ["prune"]):
            with self.subTest(args=args):
                proc = self.with_env(*args, env={"XDG_DATA_HOME": xdg}, expect_ok=False)
                self.no_traceback(proc)
                self.assertFalse(os.path.exists(xdg), "reading created XDG_DATA_HOME")

    def test_snap_creates_the_default_database(self):
        xdg = os.path.join(self.root, "xdg")
        env = dict(os.environ, XDG_DATA_HOME=xdg)
        self.real("snap", self.tree, "-q", env=env)
        self.assertTrue(os.path.isfile(os.path.join(xdg, "grew", "snapshots.db")))

    def test_empty_database_name_is_rejected(self):
        proc = run_main("--db", "", "list")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("--db needs a file name", proc.stderr)

    def test_nul_in_a_database_name_is_rejected(self):
        with self.assertRaises(SystemExit) as caught:
            g.connect("a\0b")
        self.assertIn("--db needs a file name", str(caught.exception))

    def test_default_path_that_is_a_directory_is_explained(self):
        xdg = os.path.join(self.root, "xdg")
        os.makedirs(os.path.join(xdg, "grew", "snapshots.db"))
        proc = self.with_env("list", env={"XDG_DATA_HOME": xdg}, expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.no_traceback(proc)
        self.assertIn("is a directory", proc.stderr)
        self.assertIn("XDG_DATA_HOME", proc.stderr)


class TestDatabaseErrorAdvice(Base):
    """The advice must match the cause; "delete it" destroys healthy databases (A2, A3)."""

    CASES = [
        ("database is locked", "locked"),
        ("database table is locked", "locked"),
        ("attempt to write a readonly database", "readonly"),
        ("unable to open database file", "readonly"),
        ("database or disk is full", "full"),
        ("disk I/O error", "full"),
        ("file is not a database", "corrupt"),
        ("database disk image is malformed", "corrupt"),
        ("no such table: snapshots", "corrupt"),
        ("file is not a grew database: it has tables that grew did not create", "foreign"),
        ("something nobody anticipated", "other"),
    ]

    def test_failures_are_classified_by_cause(self):
        for message, kind in self.CASES:
            with self.subTest(message=message):
                self.assertEqual(g.failure_kind(sqlite3.OperationalError(message)), kind)

    def test_advice_fits_the_cause_and_only_corruption_mentions_moving_the_file(self):
        for message, kind in self.CASES:
            with self.subTest(message=message):
                text = str(g.db_failure("/x/my db.sqlite",
                                        sqlite3.OperationalError(message)).code)
                self.assertNotRegex(text, r"(?i)delete it|\brm\b")
                if kind == "corrupt":
                    self.assertIn("mv '/x/my db.sqlite' '/x/my db.sqlite'.bad", text)
                    self.assertIn("never deletes", text)
                else:
                    self.assertNotIn("delete", text)
                    self.assertNotIn("corrupt", text)
                    self.assertNotIn("mv ", text)
                expected = {"locked": "try again", "readonly": "permissions",
                            "full": "free some space", "other": "try again",
                            "foreign": "left it alone"}.get(kind)
                if expected:
                    self.assertIn(expected, text)

    def test_corrupt_database_is_never_deleted_and_advice_is_to_move_it(self):
        with open(self.db, "w") as f:
            f.write("definitely not sqlite")
        before = digest(self.db)
        proc = self.cli("list", expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.no_traceback(proc)
        self.assertIn("corrupt", proc.stderr)
        self.assertIn("mv ", proc.stderr)
        self.assertEqual(digest(self.db), before, "grew modified the damaged file")

    def test_damaged_pages_in_a_real_database_are_reported_not_traced(self):
        for i in range(60):
            write(os.path.join(self.tree, f"d{i}", "f.bin"), 4096)
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        size = os.path.getsize(self.db)
        self.assertGreater(size, 8192, "test needs a database with more than one page")
        with open(self.db, "r+b") as f:
            f.seek(4096)
            f.write(b"\xff" * (size - 4096))
        for command in ("list", "top"):
            with self.subTest(command=command):
                proc = self.cli(command, expect_ok=False)
                self.assertEqual(proc.returncode, 1, proc.stdout)
                self.no_traceback(proc)
                self.assertIn("corrupt", proc.stderr)
                self.assertNotIn("delete it", proc.stderr)

    def test_locked_database_is_called_locked_not_corrupt(self):
        self.cli("snap", self.tree, "-q")
        holder = sqlite3.connect(self.db)
        self.addCleanup(holder.close)
        holder.execute("BEGIN IMMEDIATE")           # another writer, mid-transaction
        with mock.patch.object(g, "BUSY_SECONDS", 0.3):
            proc = self.cli("snap", self.tree, "-q", expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("another grew", proc.stderr)
        self.assertIn("try again", proc.stderr)
        self.assertNotIn("corrupt", proc.stderr)
        self.assertNotIn("delete", proc.stderr)
        holder.rollback()
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 1,
                         "the healthy database was damaged")

    def test_lock_that_outlasts_the_timeout_mid_snapshot_is_explained(self):
        """The snapshot write happens long after connect(); it used to escape as a traceback."""
        self.cli("snap", self.tree, "-q")
        holder = sqlite3.connect(self.db)
        self.addCleanup(holder.close)

        def scan_then_lock(root, **kw):
            holder.execute("BEGIN IMMEDIATE")
            return g.ScanResult({root: 10}, {root: 1}, 10, 1, 0)

        with mock.patch.object(g, "BUSY_SECONDS", 0.3), \
                mock.patch.object(g, "scan", scan_then_lock):
            proc = self.cli("snap", self.tree, "-q", expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("cannot write database", proc.stderr)
        self.assertIn("try again", proc.stderr)
        self.assertNotIn("delete", proc.stderr)
        holder.rollback()
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 1)

    def test_a_full_disk_mid_snapshot_is_explained_and_harmless(self):
        """RLIMIT_FSIZE makes writes fail the way a full disk does, for real."""
        try:
            import resource
        except ImportError:
            self.skipTest("no resource module")
        for i in range(1500):
            write(os.path.join(self.tree, f"dir{i}", "f"), 2000)
        self.cli("snap", os.path.join(self.tree, "dir1"), "-q", "--min-size", "1")

        def limit_file_size():
            resource.setrlimit(resource.RLIMIT_FSIZE, (60000, 60000))

        proc = subprocess.run(
            [sys.executable, GREW, "--db", self.db, "snap", self.tree, "-q",
             "--min-size", "1"], capture_output=True, text=True, timeout=120,
            preexec_fn=limit_file_size)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.no_traceback(proc)
        self.assertIn("cannot write database", proc.stderr)
        self.assertIn("free some space", proc.stderr)
        self.assertNotIn("delete", proc.stderr)
        self.assertNotIn("corrupt", proc.stderr)
        # Nothing half-written, and the earlier snapshot is intact.
        rows = json.loads(self.cli("--json", "list").stdout)
        self.assertEqual([r["root"] for r in rows], [os.path.join(self.tree, "dir1")])
        con = sqlite3.connect(self.db)
        try:
            self.assertEqual(con.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        finally:
            con.close()

    def test_read_only_database_is_never_told_to_delete_itself(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores file permissions")
        self.cli("snap", self.tree, "-q")
        before = digest(self.db)
        made_read_only(self, self.db)
        for args in (["snap", self.tree, "-q"], ["prune", "--keep", "0"]):
            with self.subTest(args=args):
                proc = self.cli(*args, expect_ok=False)
                self.assertEqual(proc.returncode, 1)
                self.no_traceback(proc)
                self.assertIn("permissions", proc.stderr)
                self.assertIn("--db", proc.stderr)
                self.assertNotIn("delete", proc.stderr)
                self.assertNotIn("corrupt", proc.stderr)
        self.assertEqual(digest(self.db), before)

    def test_read_only_directory_is_never_told_to_delete_the_database(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        folder = os.path.join(self.root, "dbdir")
        os.makedirs(folder)
        self.db = os.path.join(folder, "db.sqlite")
        self.cli("snap", self.tree, "-q")
        made_read_only(self, folder)
        proc = self.cli("snap", self.tree, "-q", expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.no_traceback(proc)
        self.assertIn("permissions", proc.stderr)
        self.assertNotIn("delete", proc.stderr)
        self.assertNotIn("corrupt", proc.stderr)

    def test_prune_survives_a_failed_vacuum(self):
        """The rows are gone once committed; failing to shrink the file is only a note."""
        for _ in range(3):
            self.cli("snap", self.tree, "-q")

        class NoVacuum:
            def __init__(self, db):
                self._db = db

            def execute(self, sql, *rest):
                if sql.strip().upper() == "VACUUM":
                    raise sqlite3.OperationalError("database is locked")
                return self._db.execute(sql, *rest)

            def __getattr__(self, name):
                return getattr(self._db, name)

        real_connect = g.connect
        with mock.patch.object(g, "connect",
                               lambda *a, **k: NoVacuum(real_connect(*a, **k))):
            proc = self.cli("prune", "--keep", "1")
        self.assertIn("could not shrink", proc.stderr)
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 1)

    def test_stdout_that_cannot_be_written_is_explained(self):
        if not os.path.exists("/dev/full"):
            self.skipTest("no /dev/full")
        self.cli("snap", self.tree, "-q")
        with open("/dev/full", "w") as full:
            proc = subprocess.run([sys.executable, GREW, "--db", self.db, "list"],
                                  stdout=full, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 1)
        self.no_traceback(proc)
        self.assertNotIn("Exception ignored", proc.stderr)
        self.assertIn("grew:", proc.stderr)

    def test_closed_stdout_does_not_traceback(self):
        self.cli("snap", self.tree, "-q")
        proc = subprocess.run(
            ["sh", "-c", 'exec "$0" "$@" >&-', sys.executable, GREW, "--db", self.db, "list"],
            stderr=subprocess.PIPE, text=True)
        self.no_traceback(proc)


class TestReadOnlyDatabases(Base):
    """list, top and growth must work on a database that cannot be written (B2)."""

    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores file and directory permissions")
        super().setUp()
        self.folder = os.path.join(self.root, "dbdir")
        os.makedirs(self.folder)
        self.db = os.path.join(self.folder, "db.sqlite")
        write(os.path.join(self.tree, "a/f.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent")
        write(os.path.join(self.tree, "b/f.bin"), 3 * 1048576)
        self.cli("snap", self.tree, "-q", "--apparent")
        self.commands = (["--json", "list"], ["--json", "top"],
                         ["--json", "growth", "--min-size", "1"])
        # The oracle: what the same commands print while the database is writable.
        self.expected = {tuple(c): self.cli(*c).stdout for c in self.commands}
        self.file_digest = digest(self.db)
        self.listing = sorted(os.listdir(self.folder))

    def check_works_and_leaves_the_database_alone(self, proc=False):
        for command in self.commands:
            with self.subTest(command=command):
                proc = self.cli(*command, proc=proc)
                self.no_traceback(proc)
                self.assertEqual(proc.stdout, self.expected[tuple(command)])
        self.assertEqual(digest(self.db), self.file_digest, "a read changed the database")

    def test_read_only_file(self):
        made_read_only(self, self.db)
        self.check_works_and_leaves_the_database_alone()
        self.assertEqual(sorted(os.listdir(self.folder)), self.listing,
                         "reading a read-only file left -wal or -shm files behind")

    def test_read_only_directory_leaves_no_new_files(self):
        made_read_only(self, self.folder)
        self.check_works_and_leaves_the_database_alone(proc=True)
        self.assertEqual(sorted(os.listdir(self.folder)), self.listing,
                         "reading from a read-only directory created files in it")

    def test_read_only_file_and_directory(self):
        made_read_only(self, self.db, self.folder)
        self.check_works_and_leaves_the_database_alone()

    def test_reading_a_writable_database_leaves_no_stray_files(self):
        """A mode=ro connection cannot remove its -wal and -shm files on close."""
        for command in self.commands:
            self.cli(*command)
        self.assertEqual(sorted(os.listdir(self.folder)), self.listing)


class TestSchemaChecks(Base):
    """The schema version is checked before writing; paths are declared BLOB (B3, B4)."""

    LEGACY = """
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE snapshots (id INTEGER PRIMARY KEY, ts REAL NOT NULL, root TEXT NOT NULL,
            total INTEGER NOT NULL, files INTEGER NOT NULL, dirs INTEGER NOT NULL,
            errors INTEGER NOT NULL DEFAULT 0, elapsed REAL NOT NULL DEFAULT 0,
            apparent INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE entries (snap INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
            path TEXT NOT NULL, bytes INTEGER NOT NULL, files INTEGER NOT NULL);
        CREATE INDEX entries_snap ON entries(snap);
        CREATE INDEX snapshots_root_ts ON snapshots(root, ts);
    """

    def newer_database(self):
        con = sqlite3.connect(self.db)      # rollback journal: any WAL switch would show
        con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        con.execute("INSERT INTO meta VALUES ('schema', '99')")
        con.commit()
        con.close()

    def test_newer_schema_is_refused_before_anything_is_written(self):
        self.newer_database()
        before = digest(self.db)
        for args in (["list"], ["top"], ["growth"], ["snap", self.tree, "-q"],
                     ["prune"]):
            with self.subTest(args=args):
                proc = self.cli(*args, expect_ok=False)
                self.assertEqual(proc.returncode, 1)
                self.assertIn("schema v99", proc.stderr)
                self.assertEqual(digest(self.db), before, "the refused database was changed")
        con = sqlite3.connect(self.db)
        try:
            self.assertEqual(con.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master")]
        finally:
            con.close()
        self.assertEqual(tables, ["meta", "sqlite_autoindex_meta_1"])
        self.assertEqual(sorted(os.listdir(self.root)), ["db.sqlite", "tree"])

    def test_new_databases_declare_paths_as_blob(self):
        write(os.path.join(self.tree, "a/f.bin"), 4096)
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        con = sqlite3.connect(self.db)
        try:
            def declared(table, column):
                return {r[1]: r[2] for r in con.execute(f"PRAGMA table_info({table})")}[column]
            self.assertEqual(declared("snapshots", "root"), "BLOB")
            self.assertEqual(declared("entries", "path"), "BLOB")
            self.assertEqual(con.execute("SELECT DISTINCT typeof(root) FROM snapshots"
                                         ).fetchall(), [("blob",)])
            self.assertEqual(con.execute("SELECT DISTINCT typeof(path) FROM entries"
                                         ).fetchall(), [("blob",)])
            self.assertEqual(con.execute("SELECT value FROM meta WHERE key='schema'"
                                         ).fetchone()[0], str(g.SCHEMA_VERSION))
        finally:
            con.close()
        self.assertEqual(g.SCHEMA_VERSION, 1, "the on-disk shape is compatible, no bump needed")

    def legacy_database(self, root):
        """A 1.0-shaped database whose paths were stored as TEXT."""
        con = sqlite3.connect(self.db)
        con.executescript(self.LEGACY)
        con.execute("INSERT INTO meta VALUES ('schema', '1')")
        for snap_id, total, ts in ((1, 4 * 1048576, 1000.0), (2, 9 * 1048576, 2000.0)):
            con.execute("INSERT INTO snapshots VALUES (?,?,?,?,?,?,?,?,?)",
                        (snap_id, ts, root, total, 2, 2, 0, 0.1, 1))
            con.execute("INSERT INTO entries VALUES (?,?,?,?)", (snap_id, root, total, 2))
            con.execute("INSERT INTO entries VALUES (?,?,?,?)",
                        (snap_id, root + "/big", total - 1048576, 1))
        con.commit()
        self.assertEqual(con.execute("SELECT typeof(root) FROM snapshots").fetchone()[0], "text")
        con.close()

    def test_legacy_text_rows_are_found_by_every_command(self):
        self.legacy_database(self.tree)
        listed = json.loads(self.cli("--json", "list", self.tree).stdout)
        self.assertEqual([r["id"] for r in listed], [1, 2])
        self.assertEqual({r["root"] for r in listed}, {self.tree})
        top = json.loads(self.cli("--json", "top", self.tree).stdout)
        self.assertEqual(top[0]["path"], self.tree)
        data = json.loads(self.cli("--json", "growth", self.tree, "--min-size", "1").stdout)
        self.assertEqual((data["from"]["id"], data["to"]["id"]), (1, 2))
        self.assertEqual(data["net"], 5 * 1048576)
        self.assertEqual(data["root"], self.tree)
        db = g.connect(self.db, readonly=True)
        try:       # a trailing slash and a TEXT root still find the same two rows
            self.assertEqual([r["id"] for r in g.snapshots_for(db, self.tree + "/")], [1, 2])
        finally:
            db.close()

    def test_a_new_snapshot_pairs_with_a_legacy_text_one(self):
        """The same directory stored as TEXT and as BLOB is still one root."""
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.legacy_database(self.tree)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        data = json.loads(self.cli("--json", "growth", self.tree, "--min-size", "1").stdout)
        self.assertEqual((data["from"]["id"], data["to"]["id"]), (2, 3))
        data = json.loads(self.cli("--json", "growth", "--from", "1", "--to", "3",
                                   "--min-size", "1").stdout)
        self.assertEqual(data["root"], self.tree)

    def test_prune_removes_legacy_text_rows(self):
        self.legacy_database(self.tree)
        out = json.loads(self.cli("--json", "prune", self.tree, "--keep", "1").stdout)
        self.assertEqual((out["removed"], out["ids"], out["kept"]), (1, [1], 1))
        con = sqlite3.connect(self.db)
        try:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM entries WHERE snap=1"
                                         ).fetchone()[0], 0)
        finally:
            con.close()


class TestGrowthArguments(Base):
    """Arguments that used to traceback or silently compare a snapshot with itself (A4, B5)."""

    def two_snapshots(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        write(os.path.join(self.tree, "b.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")

    def age(self, snap_id, seconds):
        con = sqlite3.connect(self.db)
        con.execute("UPDATE snapshots SET ts = ts - ? WHERE id = ?", (seconds, snap_id))
        con.commit()
        con.close()

    def test_since_without_a_unit_is_an_argument_error_not_a_traceback(self):
        self.two_snapshots()
        for bad in ("abc", "5", "0", "", "1e3d", "d", "7y", "9" * 400):
            with self.subTest(value=bad):
                proc = self.cli("growth", "--since", bad, expect_ok=False)
                self.assertEqual(proc.returncode, 2)
                self.assertIn("duration", proc.stderr)
                self.assertIn("--since", proc.stderr)
        proc = self.cli("growth", "--since", "abc", expect_ok=False, proc=True)
        self.assertEqual(proc.returncode, 2)       # and in a real process, no traceback
        self.no_traceback(proc)

    def test_a_negative_since_is_rejected(self):
        proc = self.cli("growth", "--since=-3d", expect_ok=False, proc=True)
        self.assertEqual(proc.returncode, 2)
        self.no_traceback(proc)
        self.assertIn("duration", proc.stderr)

    def test_a_zero_since_is_rejected_with_its_reason(self):
        self.two_snapshots()
        for zero in ("0s", "0d", "0.0w", "00m"):
            with self.subTest(value=zero):
                proc = self.cli("growth", "--since", zero, expect_ok=False)
                self.assertEqual(proc.returncode, 2)
                self.assertIn("greater than zero", proc.stderr)

    def test_parse_duration_rejects_zero_and_overflow(self):
        for bad in ("0s", "0.0d", "0w", "9" * 400 + "d"):
            with self.subTest(value=bad[:12]):
                with self.assertRaises(g.argparse.ArgumentTypeError):
                    g.parse_duration(bad)
        self.assertEqual(g.parse_duration("0.5s"), 0.5)

    def test_from_equal_to_to_is_rejected(self):
        self.two_snapshots()
        for same in ("1", "2"):
            with self.subTest(snapshot=same):
                proc = self.cli("growth", "--from", same, "--to", same, expect_ok=False)
                self.assertEqual(proc.returncode, 1)
                self.assertIn("same snapshot", proc.stderr)
                self.assertIn(f"#{same}", proc.stderr)
        self.cli("growth", "--from", "1", "--to", "2")      # different ids still work

    def test_from_equal_to_to_for_a_missing_id_says_it_is_missing(self):
        self.two_snapshots()
        proc = self.cli("growth", "--from", "99", "--to", "99", expect_ok=False)
        self.assertIn("no snapshot", proc.stderr)

    def test_since_beyond_the_history_falls_back_with_a_note_on_stderr(self):
        self.two_snapshots()
        proc = self.cli("--json", "growth", "--since", "52w", "--min-size", "1")
        data = json.loads(proc.stdout)                      # stdout stays pure JSON
        self.assertEqual(data["from"]["id"], 1)
        self.assertIn("note:", proc.stderr)
        self.assertIn("oldest", proc.stderr)
        self.assertIn("#1", proc.stderr)
        self.assertNotIn("note", proc.stdout)
        human = self.cli("growth", "--since", "52w", "--min-size", "1")
        self.assertIn("note:", human.stderr)
        self.assertNotIn("note:", human.stdout)

    def test_since_within_the_history_prints_no_note(self):
        self.two_snapshots()
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        self.age(1, 3 * 86400)
        self.age(2, 86400)
        for since, expected in (("2d", 1), ("12h", 2), ("1d", 2)):
            with self.subTest(since=since):
                proc = self.cli("--json", "growth", "--since", since, "--min-size", "1")
                self.assertEqual(json.loads(proc.stdout)["from"]["id"], expected)
                self.assertEqual(proc.stderr, "")
        proc = self.cli("--json", "growth", "--since", "1w", "--min-size", "1")
        self.assertEqual(json.loads(proc.stdout)["from"]["id"], 1)
        self.assertIn("note:", proc.stderr)

    def test_huge_numbers_are_arguments_errors_or_clamped_never_tracebacks(self):
        self.two_snapshots()
        huge = "9" * 400
        for args in (["snap", self.tree, "--min-size", huge],
                     ["growth", "--min-size", huge + "K"]):
            with self.subTest(args=args[:3]):
                proc = self.cli(*args, expect_ok=False, proc=True)
                self.assertEqual(proc.returncode, 2)
                self.no_traceback(proc)
                self.assertIn("too large", proc.stderr)
        top = json.loads(self.cli("--json", "top", "-n", "99999999999999999999").stdout)
        self.assertTrue(top)
        self.cli("growth", "-n", "99999999999999999999", "--min-size", "1")
        self.cli("prune", "--keep", "99999999999999999999")

    def test_parse_size_rejects_values_float_cannot_hold(self):
        with self.assertRaises(g.argparse.ArgumentTypeError):
            g.parse_size("9" * 400)
        with self.assertRaises(g.argparse.ArgumentTypeError):
            g.parse_size("9" * 30 + "P")
        self.assertEqual(g.parse_size("1.5M"), int(1.5 * 1048576))


class TestColourAlignment(Base):
    """In colour mode the columns used to drift: padding counted invisible codes (B6)."""

    def colour_database(self):
        """Deltas of different widths and both directions: +2.0M, +30.0M, -300M."""
        write_sparse(os.path.join(self.tree, "old/huge.bin"), 300 * 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        os.remove(os.path.join(self.tree, "old/huge.bin"))
        write_sparse(os.path.join(self.tree, "small/f.bin"), 2 * 1048576)
        write_sparse(os.path.join(self.tree, "medium/f.bin"), 30 * 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")

    def rows(self, text):
        """(prefix before the path, the path) for each change row of growth output.

        A path longer than the column starts with an ellipsis instead of a slash,
        as every path does when the temp directory is long (macOS).
        """
        found = [re.match(r"( +[+-]\S+ +)((?:/|…|\.\.\.)\S*)", line)
                 for line in text.splitlines()]
        return [(m.group(1), m.group(2)) for m in found if m]

    def assert_aligned(self, plain):
        rows = self.rows(plain)
        self.assertGreaterEqual(len(rows), 3, plain)
        self.assertEqual(len({len(prefix) for prefix, _ in rows}), 1,
                         f"path column is ragged:\n{plain}")

    def test_growth_columns_line_up_when_coloured(self):
        self.colour_database()
        db = g.connect(self.db, readonly=True)
        self.addCleanup(db.close)
        args = g.build_parser().parse_args(
            ["--db", self.db, "growth", "--shrink", "--min-size", "1"])
        outputs = {}
        for coloured in (True, False):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                g.cmd_growth(args, db, g.Palette(coloured))
            outputs[coloured] = out.getvalue()
        self.assertIn("\033[3", outputs[True], "the palette produced no colour")
        stripped = ANSI.sub("", outputs[True])
        self.assertEqual(stripped, outputs[False])          # oracle: the uncoloured layout
        self.assert_aligned(stripped)

    def test_growth_columns_line_up_when_every_path_is_truncated(self):
        """macOS temp directories are long enough to push every path past the
        70-column limit, which used to leave the test with no rows to check."""
        self.tree = os.path.join(self.root, "long-" + "x" * 60, "tree")
        os.makedirs(self.tree)
        self.colour_database()
        args = g.build_parser().parse_args(
            ["--db", self.db, "growth", "--shrink", "--min-size", "1"])
        db = g.connect(self.db, readonly=True)
        self.addCleanup(db.close)
        outputs = {}
        for coloured in (True, False):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                g.cmd_growth(args, db, g.Palette(coloured))
            outputs[coloured] = out.getvalue()
        stripped = ANSI.sub("", outputs[True])
        self.assertEqual(stripped, outputs[False])
        self.assertTrue(all(path.startswith("…") for _, path in self.rows(stripped)), stripped)
        self.assert_aligned(stripped)

    def run_in_terminal(self, *args, no_color_variable=False):
        """Run grew with stdout and stderr on a pseudo-terminal; return what it printed."""
        try:
            import pty
            import select
        except ImportError:
            self.skipTest("no pty module")
        env = {k: v for k, v in os.environ.items() if k != "NO_COLOR"}
        env["PYTHONIOENCODING"] = "utf-8"       # compared with in-process output, which is
        env.pop("PYTHONUTF8", None)             # never ASCII, whatever the environment says
        if no_color_variable:
            env["NO_COLOR"] = "1"
        master, slave = pty.openpty()
        proc = subprocess.Popen([sys.executable, GREW, "--db", self.db, *args],
                                stdin=subprocess.DEVNULL, stdout=slave, stderr=slave,
                                env=env, close_fds=True)
        os.close(slave)
        chunks = []
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 1.0)
                if not ready:
                    if proc.poll() is not None:
                        break
                    continue
                try:
                    data = os.read(master, 65536)
                except OSError:             # Linux reports EIO once the child is gone
                    break
                if not data:
                    break
                chunks.append(data)
        finally:
            os.close(master)
            proc.wait(timeout=60)
        self.assertEqual(proc.returncode, 0)
        return b"".join(chunks).decode("utf-8", "surrogateescape").replace("\r\n", "\n")

    def test_growth_under_a_real_terminal(self):
        self.colour_database()
        coloured = self.run_in_terminal("growth", "--shrink", "--min-size", "1")
        self.assertIn("\033[", coloured, "no colour on a terminal")
        plain = self.cli("--no-color", "growth", "--shrink", "--min-size", "1").stdout
        self.assertEqual(ANSI.sub("", coloured), plain)
        self.assert_aligned(ANSI.sub("", coloured))

    def test_other_commands_under_a_real_terminal_match_their_plain_output(self):
        self.colour_database()
        when = re.compile(r"\d+[smhdw] ago")
        for args in (["top"], ["list"]):
            with self.subTest(args=args):
                coloured = self.run_in_terminal(*args)
                self.assertIn("\033[", coloured)
                plain = self.cli("--no-color", *args).stdout
                self.assertEqual(when.sub("T", ANSI.sub("", coloured)), when.sub("T", plain))

    def test_no_color_option_wins_on_a_terminal_before_or_after_the_command(self):
        self.colour_database()
        for args in (["--no-color", "growth", "--min-size", "1"],
                     ["growth", "--no-color", "--min-size", "1"]):
            with self.subTest(args=args):
                text = self.run_in_terminal(*args)
                self.assertIn("net", text)
                self.assertNotIn("\033[", text)

    def test_no_color_variable_wins_on_a_terminal(self):
        self.colour_database()
        text = self.run_in_terminal("growth", "--min-size", "1", no_color_variable=True)
        self.assertIn("net", text)
        self.assertNotIn("\033[", text)


class TestCommandLine(Base):
    """The documented command line works as documented (C1-C3)."""

    def snapshots(self, root, count):
        for _ in range(count):
            self.cli("snap", root, "-q", "--min-size", "1")

    def test_prune_accepts_quiet_and_prints_nothing(self):
        """README's cron example, `grew prune --keep 60 -q`, used to fail: no such option."""
        self.snapshots(self.tree, 4)
        proc = self.cli("prune", "--keep", "2", "-q", proc=True)
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 2)
        proc = self.cli("prune", "--keep", "2", "--quiet", proc=True)     # nothing left to do
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))

    def test_prune_without_quiet_still_reports(self):
        self.snapshots(self.tree, 3)
        self.assertIn("removed 2 snapshot(s), kept 1", self.cli("prune", "--keep", "1").stdout)
        self.assertIn("nothing to prune", self.cli("prune", "--keep", "1").stdout)

    def test_prune_json_when_something_is_removed(self):
        self.snapshots(self.tree, 4)
        before = [r["id"] for r in json.loads(self.cli("--json", "list").stdout)]
        data = json.loads(self.cli("--json", "prune", "--keep", "1").stdout)
        after = [r["id"] for r in json.loads(self.cli("--json", "list").stdout)]
        self.assertEqual(set(data), {"root", "removed", "ids", "kept", "keep", "reclaimed"})
        self.assertEqual(data["ids"], sorted(set(before) - set(after)))
        self.assertEqual((data["removed"], data["kept"], data["keep"], data["root"]),
                         (3, 1, 1, None))
        self.assertIs(data["reclaimed"], True)

    def test_prune_json_when_there_is_nothing_to_prune(self):
        self.snapshots(self.tree, 2)
        data = json.loads(self.cli("--json", "prune", "--keep", "5", self.tree).stdout)
        self.assertEqual(data, {"root": self.tree, "removed": 0, "ids": [], "kept": 2,
                                "keep": 5, "reclaimed": True})
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 2)

    def test_prune_json_on_an_empty_database(self):
        data = json.loads(self.cli("--json", "prune").stdout)
        self.assertEqual(data, {"root": None, "removed": 0, "ids": [], "kept": 0,
                                "keep": 20, "reclaimed": True})
        self.assertFalse(os.path.exists(self.db), "pruning nothing created a database")

    def test_prune_json_with_quiet_still_prints_json(self):
        self.snapshots(self.tree, 2)
        data = json.loads(self.cli("--json", "prune", "--keep", "1", "-q").stdout)
        self.assertEqual(data["removed"], 1)

    def test_json_and_no_color_work_after_the_subcommand_too(self):
        write(os.path.join(self.tree, "a/f.bin"), 2 * 1048576)
        self.snapshots(self.tree, 3)
        commands = (["list"], ["top"], ["growth", "--min-size", "1"],
                    ["prune", "--keep", "9"])
        for command in commands:
            with self.subTest(command=command):
                before = run_main("--db", self.db, "--json", *command)
                after = run_main("--db", self.db, command[0], "--json", *command[1:])
                self.assertEqual(before.returncode, 0, before.stderr)
                self.assertEqual(after.returncode, 0, after.stderr)
                self.assertEqual(json.loads(before.stdout), json.loads(after.stdout))
        snap = json.loads(run_main("snap", self.tree, "--db", self.db, "--json").stdout)
        self.assertEqual(snap["root"], self.tree)
        self.assertEqual(run_main("list", "--db", self.db, "--no-color").returncode, 0)

    def test_global_options_given_before_the_command_survive_the_subparser(self):
        """A subparser's own default must not overwrite what came before the command."""
        write(os.path.join(self.tree, "a/f.bin"), 2 * 1048576)
        self.snapshots(self.tree, 2)
        proc = run_main("--json", "--db", self.db, "list", "--no-color")
        self.assertEqual(len(json.loads(proc.stdout)), 2)
        proc = run_main("--db", self.db, "--json", "top")
        self.assertTrue(json.loads(proc.stdout))
        args = g.build_parser().parse_args(["--db", "X", "--json", "--no-color", "list"])
        self.assertEqual((args.db, args.json, args.no_color), ("X", True, True))
        args = g.build_parser().parse_args(["list"])
        self.assertEqual((args.db, args.json, args.no_color), (None, False, False))

    def test_every_subcommand_help_mentions_the_global_options(self):
        for command in ("snap", "growth", "top", "list", "prune"):
            with self.subTest(command=command):
                text = run_main(command, "--help").stdout
                for option in ("--db", "--json", "--no-color"):
                    self.assertIn(option, text)

    def test_a_path_without_snapshots_is_named_with_the_other_roots(self):
        other = os.path.join(self.root, "other")
        third = os.path.join(self.root, "third")
        nowhere = os.path.join(self.root, "nowhere")
        for folder in (other, third):
            os.makedirs(folder)
        self.snapshots(self.tree, 1)
        for count, extra in ((1, "1 other root has snapshots"), (2, "2 other roots have snapshots")):
            if count == 2:
                self.snapshots(other, 1)
            with self.subTest(other_roots=count):
                top = self.cli("top", nowhere, expect_ok=False)
                self.assertEqual(top.returncode, 1)
                lst = self.cli("list", nowhere)
                prune = self.cli("prune", nowhere)
                for text in (top.stderr, lst.stdout, prune.stderr):
                    self.assertIn(nowhere, text)
                    self.assertIn(extra, text)
                    self.assertIn("grew list", text)
                    self.assertNotIn("no snapshots yet", text)
                self.assertEqual((lst.returncode, prune.returncode), (0, 0))
        growth = self.cli("growth", nowhere, expect_ok=False)
        self.assertEqual(growth.returncode, 1)
        self.assertIn(nowhere, growth.stderr)
        self.assertIn("two snapshots", growth.stderr)
        self.assertIn("grew list", growth.stderr)
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 2,
                         "pruning an unknown path removed something")

    def test_unknown_path_in_json_and_quiet_modes(self):
        self.snapshots(self.tree, 1)
        nowhere = os.path.join(self.root, "nowhere")
        self.assertEqual(json.loads(self.cli("--json", "list", nowhere).stdout), [])
        data = json.loads(self.cli("--json", "prune", nowhere).stdout)
        self.assertEqual((data["removed"], data["kept"], data["root"]), (0, 0, nowhere))
        quiet = self.cli("prune", nowhere, "-q", proc=True)
        self.assertEqual((quiet.returncode, quiet.stdout, quiet.stderr), (0, "", ""))

    def test_an_empty_database_gets_the_plain_message(self):
        for args in (["top"], ["top", self.tree]):
            with self.subTest(args=args):
                proc = self.cli(*args, expect_ok=False)
                self.assertEqual(proc.returncode, 1)
                self.assertIn("no snapshots yet", proc.stderr)
        self.assertIn("no snapshots yet", self.cli("list").stdout)
        self.assertIn(self.tree, self.cli("list", self.tree).stdout)

    def test_documented_commands_parse(self):
        """Every `grew ...` command line in the README and man page must be accepted.

        Only code is checked: fenced blocks and `inline code` in the README,
        and the .B example lines in the man page. Prose is free to say "grew".
        """
        parser = g.build_parser()
        seen = 0
        for name in ("README.md", "grew.1"):
            with open(os.path.join(HERE, name), encoding="utf-8") as f:
                text = f.read()
            if name == "README.md":
                chunks = re.findall(r"```.*?```", text, re.S) + re.findall(r"`[^`\n]+`", text)
            else:
                text = re.sub(r"\\f[BIRP]|\\&", "", text).replace("\\-", "-")
                chunks = [line[3:] for line in text.splitlines() if line.startswith(".B ")]
            for chunk in chunks:
                for match in re.finditer(
                        r"\bgrew\s+((?:--[a-z-]+\s+)*(?:snap|growth|top|list|prune)\b[^\n`|&#]*)",
                        chunk):
                    command = match.group(1).strip()
                    with self.subTest(source=name, command=command):
                        seen += 1
                        try:
                            with contextlib.redirect_stdout(io.StringIO()), \
                                    contextlib.redirect_stderr(io.StringIO()):
                                parser.parse_args(shlex.split(command))
                        except SystemExit as exc:
                            # --help exits 0 after printing; only a usage error is a rejection.
                            if exc.code not in (0, None):
                                self.fail(f"{name} documents a command grew rejects: grew {command}")
        self.assertGreater(seen, 10, "found suspiciously few documented commands")

    def test_the_version_agrees_between_the_tool_the_man_page_and_the_docs(self):
        shown = run_main("--version").stdout.strip()
        self.assertEqual(shown, f"grew {g.__version__}")
        with open(os.path.join(HERE, "grew.1"), encoding="utf-8") as f:
            header = re.search(r'^\.TH GREW 1 "[^"]*" "grew ([^"]+)"', f.read(), re.M)
        self.assertIsNotNone(header, "grew.1 has no .TH line")
        self.assertEqual(header.group(1), g.__version__)

class TestParallelStartup(Base):
    """Several grews creating the same fresh database at once must all succeed (B1).

    The first version ran PRAGMA journal_mode=WAL, CREATE TABLE and
    INSERT OR IGNORE unguarded in every process, and about one run in four lost
    the race with "database is locked".
    """

    use_proc = True

    GATED = (
        "import importlib.machinery, importlib.util, os, sys, time\n"
        "spec = importlib.util.spec_from_loader('grewmod',\n"
        "    importlib.machinery.SourceFileLoader('grewmod', sys.argv[1]))\n"
        "g = importlib.util.module_from_spec(spec); sys.modules['grewmod'] = g\n"
        "spec.loader.exec_module(g)\n"
        # A gate that never opens must not leave this process spinning: if the test
        # run is killed before it creates the gate, its temporary directory is
        # gone and the file can never appear. Give up after a deadline, or as
        # soon as the parent has gone.
        "parent = int(os.environ.get('GREW_GATE_PARENT') or os.getppid())\n"
        "deadline = time.monotonic() + float(os.environ.get('GREW_GATE_SECONDS', '60'))\n"
        "while not os.path.exists(sys.argv[2]):\n"
        "    if os.getppid() != parent or time.monotonic() > deadline:\n"
        "        sys.exit(3)\n"
        "    time.sleep(0.0005)\n"
        "sys.exit(g.main(sys.argv[3:]))\n"
    )

    def stampede(self, db, commands, name):
        """Start one interpreter per command, hold them at a gate, release them together."""
        gate = os.path.join(self.root, f"gate-{name}")
        env = dict(os.environ, GREW_GATE_PARENT=str(os.getpid()))
        procs = [subprocess.Popen(
            [sys.executable, "-c", self.GATED, GREW, gate, "--db", db, *command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env) for command in commands]
        try:
            time.sleep(0.3)                      # let every one reach the gate
            open(gate, "w").close()
            failures = []
            for p in procs:
                _, err = p.communicate(timeout=120)
                if p.returncode != 0:
                    failures.append(err.decode())
            return failures
        finally:
            for p in procs:                      # never leave one behind, whatever happened
                if p.poll() is None:
                    p.kill()
                    p.wait()

    def busy_connection(self, failures, matching):
        """A connection whose first `failures` statements matching `matching` say "locked"."""
        real = sqlite3.connect(":memory:")
        real.row_factory = sqlite3.Row
        self.addCleanup(real.close)
        state = {"left": failures}

        class Busy:
            def execute(self, sql, *rest):
                if matching in sql and state["left"] > 0:
                    state["left"] -= 1
                    if real.in_transaction:
                        real.rollback()
                    raise sqlite3.OperationalError("database is locked")
                return real.execute(sql, *rest)

            def __getattr__(self, name):
                return getattr(real, name)

        return Busy(), state, real

    def test_initialisation_retries_when_the_database_is_busy(self):
        """The two steps that lost the race: switching to WAL, and the schema write.

        Deterministic, unlike the stampede: it fails every time if the retry is removed.
        """
        for matching in ("journal_mode=WAL", "BEGIN IMMEDIATE", "CREATE TABLE"):
            with self.subTest(statement=matching):
                db, state, real = self.busy_connection(3, matching)
                with mock.patch.object(g.time, "sleep"):
                    g._initialise(db, "x")
                self.assertEqual(state["left"], 0, "the busy statement was never retried")
                tables = {r[0] for r in real.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
                self.assertTrue({"meta", "snapshots", "entries"} <= tables)
                self.assertEqual(real.execute("SELECT value FROM meta").fetchone()[0], "1")

    def test_initialisation_gives_up_with_a_locked_error_after_the_deadline(self):
        db, _, _ = self.busy_connection(10 ** 9, "BEGIN IMMEDIATE")
        with mock.patch.object(g, "BUSY_SECONDS", 0.2):
            with self.assertRaises(sqlite3.OperationalError) as caught:
                g._initialise(db, "x")
        self.assertEqual(g.failure_kind(caught.exception), "locked")

    def test_initialisation_does_not_retry_other_errors(self):
        db, state, _ = self.busy_connection(0, "never")

        class Broken:
            calls = 0

            def execute(self, sql, *rest):
                Broken.calls += 1
                raise sqlite3.OperationalError("attempt to write a readonly database")

            def __getattr__(self, name):
                return getattr(db, name)

        with self.assertRaises(sqlite3.OperationalError):
            g._initialise(Broken(), "x")
        self.assertEqual(Broken.calls, 1)

    def test_simultaneous_first_snapshots_on_fresh_databases(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        for round_number in range(5):
            with self.subTest(round=round_number):
                db = os.path.join(self.root, f"fresh{round_number}.sqlite")
                failures = self.stampede(db, [["snap", self.tree, "-q"]] * 10,
                                         f"snap{round_number}")
                self.assertEqual(failures, [])
                con = sqlite3.connect(db)
                try:
                    self.assertEqual(con.execute("SELECT COUNT(*) FROM snapshots"
                                                 ).fetchone()[0], 10)
                    self.assertEqual(con.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                    self.assertEqual(con.execute("SELECT COUNT(*) FROM meta").fetchone()[0], 1)
                    self.assertEqual(con.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                finally:
                    con.close()

    def test_simultaneous_readers_and_pruners_on_a_fresh_name(self):
        """Commands that do not create the database must not fail on a missing one."""
        db = os.path.join(self.root, "readers.sqlite")
        write(os.path.join(self.tree, "a.bin"), 1048576)
        failures = self.stampede(db, [["list"], ["prune", "-q"], ["--json", "list"]] * 4,
                                 "readers")
        self.assertEqual(failures, [])
        self.assertFalse(os.path.exists(db))

    def test_snapshots_and_prunes_at_the_same_time(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        for _ in range(3):
            self.cli("snap", self.tree, "-q")
        procs = [subprocess.Popen(
            [sys.executable, GREW, "--db", self.db, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for args in (["snap", self.tree, "-q"], ["prune", "--keep", "2", "-q"],
                         ["snap", self.tree, "-q"], ["prune", "--keep", "2", "-q"],
                         ["--json", "list"], ["snap", self.tree, "-q"])]
        failures = []
        for p in procs:
            _, err = p.communicate(timeout=120)
            if p.returncode != 0:
                failures.append(err.decode())
        self.assertEqual(failures, [])
        con = sqlite3.connect(self.db)
        try:
            self.assertEqual(con.execute(
                "SELECT COUNT(*) FROM entries WHERE snap NOT IN (SELECT id FROM snapshots)"
            ).fetchone()[0], 0)
        finally:
            con.close()



# --------------------------------------------------------------------------- #
# round four: what the second round of reviewers found
# --------------------------------------------------------------------------- #

class TestDuHelpers(Base):
    """The du oracle must run on BSD du too, or the macOS job crashes (D2)."""

    # Behaves like BSD du: no long options, sizes in BLOCKSIZE units only, and
    # no GNU variables that would change the answer.
    FAKE_DU = (
        "#!/bin/sh\n"
        'for a in "$@"; do case "$a" in\n'
        '  -s|-x) ;;\n'
        '  -*) echo "du: illegal option -- $a" >&2; exit 64;;\n'
        "esac; done\n"
        '[ "$BLOCKSIZE" = 512 ] || { echo "du: BLOCKSIZE is not 512" >&2; exit 65; }\n'
        '[ -z "$BLOCK_SIZE$DU_BLOCK_SIZE$POSIXLY_CORRECT" ] || '
        '{ echo "du: GNU variable set" >&2; exit 66; }\n'
        'for a in "$@"; do last=$a; done\n'
        'printf "7\\t%s\\n" "$last"\n'
    )

    def fake_du_path(self):
        folder = os.path.join(self.root, "bin")
        os.makedirs(folder)
        exe = os.path.join(folder, "du")
        with open(exe, "w") as f:
            f.write(self.FAKE_DU)
        os.chmod(exe, 0o755)
        return folder

    def test_both_du_helpers_work_against_a_du_that_behaves_like_bsd(self):
        import test_grew
        polluted = {"PATH": self.fake_du_path() + os.pathsep + os.environ["PATH"],
                    "BLOCKSIZE": "1", "BLOCK_SIZE": "1", "DU_BLOCK_SIZE": "1",
                    "POSIXLY_CORRECT": "1"}
        with mock.patch.dict(os.environ, polluted):
            for one_fs in (True, False):
                with self.subTest(one_fs=one_fs):
                    self.assertEqual(du_run(self.tree, one_fs), (7 * 512, 0))
            self.assertEqual(du_bytes(self.tree), 7 * 512)
            self.assertEqual(test_grew.du_bytes(self.tree), 7 * 512)

    def test_the_fake_du_really_rejects_the_gnu_only_spelling(self):
        """Guards the guard: the old --block-size=1 must fail against it."""
        env = dict(os.environ, PATH=self.fake_du_path() + os.pathsep + os.environ["PATH"])
        proc = subprocess.run(["du", "-s", "--block-size=1", self.tree], env=env,
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 64)

    def test_the_command_uses_only_short_options_both_du_implementations_share(self):
        for one_fs in (True, False):
            command = du_command("/x", one_fs)
            self.assertEqual(command[0], "du")
            self.assertEqual(command[-1], "/x")
            self.assertTrue(set(command[1:-1]) <= {"-s", "-x"}, command)
        self.assertEqual(du_environment()["BLOCKSIZE"], "512")


class TestApparentSize(Base):
    """--apparent matches du --apparent-size: files and symlinks, not directories."""

    def build(self):
        write(os.path.join(self.tree, "a/one.bin"), 5000)
        write(os.path.join(self.tree, "a/b/two.bin"), 12345)
        write(os.path.join(self.tree, "c/three.bin"), 77)
        os.makedirs(os.path.join(self.tree, "empty/deeper"))
        self.targets = ["x" * 5, "y" * 40, "z" * 90]
        for i, target in enumerate(self.targets):
            os.symlink(target, os.path.join(self.tree, "a", f"link{i}"))
        os.link(os.path.join(self.tree, "a/one.bin"), os.path.join(self.tree, "c/hard.bin"))

    def test_total_is_file_bytes_plus_symlink_bytes_and_no_directories(self):
        self.build()
        links = sum(len(t) for t in self.targets)
        res = g.scan(self.tree, apparent=True, min_size=0)
        self.assertEqual(res.total, 5000 + 12345 + 77 + links)
        self.assertEqual(res.total, apparent_bytes(self.tree))       # the lstat oracle
        # (a/one.bin and its hardlink c/hard.bin are billed to whichever the walk
        # meets first, so only directories without it are pinned here.)
        self.assertEqual(res.sizes[os.path.join(self.tree, "a/b")], 12345)
        self.assertEqual(res.sizes[os.path.join(self.tree, "empty")], 0)

    def test_symlink_inode_is_counted_in_apparent_mode_too(self):
        """Dropping the symlink's own size is invisible when st_blocks is 0 (ext4,
        tmpfs); an apparent scan, where st_size is not zero, shows it on every
        filesystem."""
        self.build()
        with_links = g.scan(self.tree, apparent=True, min_size=0).total
        for i in range(3):
            os.remove(os.path.join(self.tree, "a", f"link{i}"))
        without = g.scan(self.tree, apparent=True, min_size=0).total
        self.assertEqual(with_links - without, sum(len(t) for t in self.targets))
        self.assertGreater(with_links - without, 0)

    def test_matches_gnu_du_apparent_size_when_available(self):
        self.build()
        proc = subprocess.run(["du", "-s", "--apparent-size", "--block-size=1", self.tree],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            self.skipTest("this du has no --apparent-size (BSD)")
        self.assertEqual(g.scan(self.tree, apparent=True, min_size=0).total,
                         int(proc.stdout.split()[0]))

    def test_a_directory_is_never_billed_in_apparent_mode_whatever_it_reports(self):
        """On ext4 a directory reports st_size 4096 and 8 blocks; on tmpfs it reports
        a size that grows and no blocks. Pretend to be ext4 so the answer does not
        depend on the filesystem the tests happen to run on."""
        self.build()
        real_stat = os.stat

        def ext4_like(path, *args, **kwargs):
            st = real_stat(path, *args, **kwargs)
            if not stat.S_ISDIR(st.st_mode):
                return st
            return types.SimpleNamespace(st_mode=st.st_mode, st_dev=st.st_dev,
                                         st_ino=st.st_ino, st_nlink=st.st_nlink,
                                         st_size=4096, st_blocks=8)

        with mock.patch.object(os, "stat", ext4_like):
            apparent = g.scan(self.tree, apparent=True, min_size=0)
            allocated = g.scan(self.tree, apparent=False, min_size=0)
        self.assertEqual(apparent.total, apparent_bytes(self.tree))
        directories, blocks, seen = 0, 0, set()
        for folder, dirs, files in os.walk(self.tree):
            directories += 1
            links = [d for d in dirs if os.path.islink(os.path.join(folder, d))]
            for name in files + links:
                st = os.lstat(os.path.join(folder, name))
                if st.st_nlink > 1:
                    if (st.st_dev, st.st_ino) in seen:
                        continue
                    seen.add((st.st_dev, st.st_ino))
                blocks += st.st_blocks * 512
        # Allocated mode does bill each directory, at what it reports (8 blocks here).
        self.assertEqual(allocated.total, blocks + directories * 4096)

    def test_an_empty_directory_is_zero_bytes_not_its_st_size(self):
        os.makedirs(os.path.join(self.tree, "e"))
        self.assertEqual(g.scan(os.path.join(self.tree, "e"), apparent=True,
                                min_size=0).total, 0)

    def test_allocated_mode_still_counts_directory_inodes(self):
        self.build()
        self.assertEqual(g.scan(self.tree, apparent=False, min_size=0).total,
                         du_bytes(self.tree))


class TestInterruption(Base):
    """Ctrl-C is a message and status 130, never a traceback (A2)."""

    def test_keyboard_interrupt_is_reported_and_nothing_is_saved(self):
        with mock.patch.object(g, "scan", side_effect=KeyboardInterrupt):
            try:
                proc = self.cli("snap", self.tree, "-q", expect_ok=False)
            except KeyboardInterrupt:       # unittest would otherwise abort the whole run
                self.fail("Ctrl-C escaped main() as a traceback")
        self.assertEqual(proc.returncode, 130)
        self.assertIn("interrupted", proc.stderr)
        self.no_traceback(proc)
        self.assertEqual(json.loads(self.cli("--json", "list").stdout), [])

    def test_a_real_sigint_during_a_scan(self):
        import signal
        script = (
            "import importlib.machinery, importlib.util, signal, sys, time\n"
            "spec = importlib.util.spec_from_loader('grewmod',\n"
            "    importlib.machinery.SourceFileLoader('grewmod', sys.argv[1]))\n"
            "g = importlib.util.module_from_spec(spec); sys.modules['grewmod'] = g\n"
            "spec.loader.exec_module(g)\n"
            # A background shell can leave SIGINT ignored, which would make
            # this test wait forever; a terminal user always has the default.
            "signal.signal(signal.SIGINT, signal.default_int_handler)\n"
            "def slow_scan(*a, **k):\n"
            "    print('ready', flush=True)\n"
            "    time.sleep(60)\n"
            "g.scan = slow_scan\n"
            "sys.exit(g.main(sys.argv[2:]))\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", script, GREW, "--db", self.db, "snap", self.tree],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(), "ready")
            proc.send_signal(signal.SIGINT)
            _, err = proc.communicate(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 130, err)
        self.assertIn("interrupted", err)
        self.assertNotIn("Traceback", err)
        self.assertEqual(json.loads(self.cli("--json", "list").stdout), [])


class TestUnusualDatabaseFiles(Base):
    """Files that are not a healthy grew database, and what they are told (B2, B3, A3)."""

    def listing(self):
        return sorted(os.listdir(self.root))

    def test_an_existing_empty_file_is_an_empty_database(self):
        open(self.db, "w").close()
        before = self.listing()
        for args, status in ((["list"], 0), (["--json", "list"], 0), (["top"], 1),
                             (["growth"], 1), (["prune"], 0), (["--json", "prune"], 0)):
            with self.subTest(args=args):
                proc = self.cli(*args, expect_ok=False)
                self.assertEqual(proc.returncode, status, proc.stderr)
                self.no_traceback(proc)
                self.assertNotIn("corrupt", proc.stderr)
                self.assertNotIn("mv ", proc.stderr)
        self.assertIn("no snapshots yet", self.cli("list").stdout)
        self.assertIn("no snapshots yet", self.cli("top", expect_ok=False).stderr)
        self.assertEqual(os.path.getsize(self.db), 0, "a read command filled in the file")
        self.assertEqual(self.listing(), before)

    def test_snap_fills_in_an_existing_empty_file(self):
        open(self.db, "w").close()
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q")
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 1)

    def test_a_database_with_only_the_meta_table_is_empty_not_corrupt(self):
        """An initialisation that never finished: nothing was recorded."""
        con = sqlite3.connect(self.db)
        con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        con.execute("INSERT INTO meta VALUES ('schema', '1')")
        con.commit()
        con.close()
        before = digest(self.db)
        self.assertIn("no snapshots yet", self.cli("list").stdout)
        self.assertEqual(self.cli("top", expect_ok=False).returncode, 1)
        self.assertEqual(digest(self.db), before)

    def test_missing_indexes_do_not_hide_the_rows_that_are_there(self):
        """Read mode used to call such a database empty: a quiet wrong answer."""
        con = sqlite3.connect(self.db)
        con.executescript(TestSchemaChecks.LEGACY.replace(
            "CREATE INDEX entries_snap ON entries(snap);", "").replace(
            "CREATE INDEX snapshots_root_ts ON snapshots(root, ts);", ""))
        con.execute("INSERT INTO meta VALUES ('schema', '1')")
        for snap_id, total, ts in ((1, 4 * 1048576, 1000.0), (2, 9 * 1048576, 2000.0)):
            con.execute("INSERT INTO snapshots VALUES (?,?,?,?,?,?,?,?,?)",
                        (snap_id, ts, self.tree, total, 2, 2, 0, 0.1, 1))
            con.execute("INSERT INTO entries VALUES (?,?,?,?)", (snap_id, self.tree, total, 2))
        con.commit()
        indexes = con.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index' "
                              "AND name NOT LIKE 'sqlite_%'").fetchone()[0]
        con.close()
        self.assertEqual(indexes, 0)
        self.assertEqual([r["id"] for r in json.loads(self.cli("--json", "list").stdout)],
                         [1, 2])
        self.assertEqual(json.loads(self.cli("--json", "top").stdout)[0]["bytes"],
                         9 * 1048576)

    def foreign_database(self):
        con = sqlite3.connect(self.db)
        con.execute("CREATE TABLE snapshots (x)")        # someone else's table
        con.execute("INSERT INTO snapshots VALUES (1)")
        con.commit()
        con.close()
        return digest(self.db)

    def test_a_foreign_sqlite_database_is_refused_and_left_untouched(self):
        before = self.foreign_database()
        for args in (["list"], ["top"], ["growth"], ["snap", self.tree, "-q"],
                     ["prune"], ["--json", "list"]):
            with self.subTest(args=args):
                proc = self.cli(*args, expect_ok=False)
                self.assertEqual(proc.returncode, 1, proc.stdout)
                self.no_traceback(proc)
                self.assertIn("another program", proc.stderr)
                self.assertIn("--db", proc.stderr)
                self.assertNotRegex(proc.stderr, r"corrupt|delete|mv ")
                self.assertEqual(digest(self.db), before, "grew modified a foreign database")
        con = sqlite3.connect(self.db)
        try:
            names = {r[0] for r in con.execute("SELECT name FROM sqlite_master")}
        finally:
            con.close()
        self.assertEqual(names, {"snapshots"}, "grew added its tables to a foreign database")
        self.assertEqual(self.listing(), ["db.sqlite", "tree"])

    def test_a_database_that_cannot_be_read_says_so_without_mentioning_writing(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores file permissions")
        self.cli("snap", self.tree, "-q")
        before = digest(self.db)
        made_read_only(self, self.db)
        os.chmod(self.db, 0)
        for args in (["list"], ["top"], ["growth"]):
            with self.subTest(args=args):
                proc = self.cli(*args, expect_ok=False)
                self.assertEqual(proc.returncode, 1)
                self.no_traceback(proc)
                self.assertIn("cannot read database", proc.stderr)
                self.assertIn("permission", proc.stderr)
                self.assertNotRegex(proc.stderr, r"write|delete|corrupt|disk")
        os.chmod(self.db, 0o600)
        self.assertEqual(digest(self.db), before)

    def test_the_readonly_advice_is_about_use_not_only_writing(self):
        text = str(g.db_failure("/x/db", sqlite3.OperationalError(
            "unable to open database file")).code)
        self.assertIn("no permission", text)
        self.assertNotIn("cannot write there", text)

    def test_a_device_or_fifo_is_not_blamed_on_permissions_or_a_full_disk(self):
        targets = ["/dev/null"] if os.path.exists("/dev/null") else []
        fifo = os.path.join(self.root, "fifo.db")
        os.mkfifo(fifo)
        targets.append(fifo)
        for target in targets:
            for args in (["snap", self.tree, "-q"], ["list"], ["prune"]):
                with self.subTest(target=target, args=args):
                    proc = run_main("--db", target, *args)
                    self.assertEqual(proc.returncode, 1)
                    self.assertIn("not a regular file", proc.stderr)
                    self.assertNotRegex(proc.stderr, r"permission|disk is full|delete")

    def test_a_non_regular_default_database_is_explained_too(self):
        xdg = os.path.join(self.root, "xdg")
        os.makedirs(os.path.join(xdg, "grew"))
        os.mkfifo(os.path.join(xdg, "grew", "snapshots.db"))
        proc = self.with_env("list", env={"XDG_DATA_HOME": xdg}, expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("not a regular file", proc.stderr)

    def test_a_read_only_file_in_a_writable_directory_leaves_the_directory_alone(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores file permissions")
        write(os.path.join(self.tree, "a/f.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent")
        self.cli("snap", self.tree, "-q", "--apparent")
        made_read_only(self, self.db)
        before = self.listing()
        for args in (["list"], ["top"], ["growth", "--min-size", "1"]):
            with self.subTest(args=args):
                self.cli(*args)
                self.assertEqual(self.listing(), before, "reading created -wal or -shm files")

    def test_a_read_only_wal_database_with_unmerged_changes_is_read_in_full(self):
        """-wal and -shm beside the file hold rows that immutable=1 would not see."""
        if os.geteuid() == 0:
            self.skipTest("root ignores file permissions")
        writer = sqlite3.connect(self.db)
        self.addCleanup(writer.close)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        for statement in g.SCHEMA:
            writer.execute(statement)
        writer.execute("INSERT INTO meta VALUES ('schema', '1')")
        writer.execute("INSERT INTO snapshots (ts, root, total, files, dirs) "
                       "VALUES (1000.0, ?, 4096, 1, 1)", (g.enc(self.tree),))
        writer.commit()
        self.assertTrue(os.path.exists(self.db + "-wal"))
        made_read_only(self, self.db)
        rows = json.loads(self.cli("--json", "list").stdout)
        self.assertEqual([r["total"] for r in rows], [4096])

    def test_an_ordinary_connection_would_leave_files_behind_on_a_read_only_file(self):
        """Pins the writable check in _open_readonly: an ordinary connection on a
        read-only WAL file creates -wal and -shm, which immutable=1 never does."""
        if os.geteuid() == 0:
            self.skipTest("root ignores file permissions")
        self.cli("snap", self.tree, "-q")
        made_read_only(self, self.db)
        before = self.listing()
        db, _ = g._open_readonly(self.db)
        db.close()
        self.assertEqual(self.listing(), before)


class TestOutputFailures(Base):
    """A full, closed or unencodable output is never a traceback (A2, other)."""

    def test_snap_to_a_full_stdout_still_succeeds_because_the_snapshot_is_saved(self):
        if not os.path.exists("/dev/full"):
            self.skipTest("no /dev/full")
        write(os.path.join(self.tree, "a.bin"), 1048576)
        with open("/dev/full", "w") as full:
            proc = subprocess.run([sys.executable, GREW, "--db", self.db, "snap", self.tree],
                                  stdout=full, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("snapshot #1 was saved", proc.stderr)
        self.no_traceback(proc)
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 1)

    def test_snap_to_a_closed_stdout_still_succeeds(self):
        proc = subprocess.run(
            ["sh", "-c", 'exec "$0" "$@" >&-', sys.executable, GREW, "--db", self.db,
             "snap", self.tree], stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.no_traceback(proc)
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 1)

    def test_snap_to_a_closed_pipe_ends_quietly(self):
        proc = subprocess.Popen([sys.executable, GREW, "--db", self.db, "snap", self.tree],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.stdout.close()
        _, err = proc.communicate(timeout=60)
        self.assertNotIn(b"Traceback", err)
        self.assertEqual(proc.returncode, 0, err)

    def test_a_full_stderr_does_not_turn_the_exit_status_into_120(self):
        if not os.path.exists("/dev/full"):
            self.skipTest("no /dev/full")
        with open("/dev/full", "w") as full:
            proc = subprocess.run([sys.executable, GREW, "--db", self.db, "top"],
                                  stdout=subprocess.PIPE, stderr=full, text=True)
        self.assertEqual(proc.returncode, 1)           # no snapshots: a plain failure
        with open("/dev/full", "w") as full:
            proc = subprocess.run([sys.executable, GREW, "--db", self.db, "snap", self.tree],
                                  stdout=subprocess.PIPE, stderr=full, text=True)
        self.assertEqual(proc.returncode, 0)           # progress is only a courtesy
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 1)

    def two_snapshots_with_a_long_path(self, name="d"):
        deep = os.path.join(self.tree, name + "-" + "d" * 40, "e" * 40)
        write(os.path.join(deep, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        write(os.path.join(deep, "b.bin"), 2 * 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")

    def test_a_terminal_that_cannot_show_the_arrow_or_ellipsis_gets_ascii(self):
        self.two_snapshots_with_a_long_path()
        for encoding in ("ascii", "latin-1"):
            env = dict(os.environ, PYTHONIOENCODING=encoding, PYTHONUTF8="0")
            for args in (["growth", "--min-size", "1"], ["top"], ["list"]):
                with self.subTest(encoding=encoding, args=args):
                    proc = self.cli(*args, env=env)
                    self.no_traceback(proc)
                    self.assertNotIn("UnicodeEncodeError", proc.stderr)
                    self.assertNotIn("→", proc.stdout)
                    self.assertNotIn("…", proc.stdout)
                    if args[0] == "growth":
                        self.assertIn(" -> ", proc.stdout)
                    if args[0] != "list":
                        self.assertIn("...", proc.stdout)

    def test_a_non_ascii_name_on_an_ascii_terminal_is_escaped_not_a_traceback(self):
        try:
            self.two_snapshots_with_a_long_path("üñï")
        except UnicodeEncodeError:
            self.skipTest("the filesystem encoding cannot hold non-ASCII names")
        env = dict(os.environ, PYTHONIOENCODING="ascii", PYTHONUTF8="0")
        for args in (["top"], ["growth", "--min-size", "1"], ["--json", "top"]):
            with self.subTest(args=args):
                proc = self.cli(*args, env=env)
                self.no_traceback(proc)
                self.assertNotRegex(proc.stdout, r"[^\x00-\x7f]")

    def test_utf8_output_keeps_the_arrow_and_ellipsis(self):
        self.two_snapshots_with_a_long_path()
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        proc = subprocess.run([sys.executable, GREW, "--db", self.db, "growth",
                               "--min-size", "1"], capture_output=True, env=env, timeout=120)
        out = proc.stdout.decode("utf-8")        # not the locale: it may be ASCII
        self.assertIn("→", out)
        self.assertIn("…", out)

    def test_printable_chooses_by_the_stream_encoding(self):
        class Stream:
            def __init__(self, encoding):
                self.encoding = encoding

        for encoding, expected in (("utf-8", "→"), ("UTF-8", "→"), ("ascii", "->"),
                                   ("latin-1", "->"), ("no-such-codec", "->"),
                                   (None, "→")):
            with self.subTest(encoding=encoding):
                with mock.patch.object(g.sys, "stdout", Stream(encoding)):
                    self.assertEqual(g.printable("→", "->"), expected)


class TestUnexpectedData(Base):
    """sqlite stores any type in any column; a hand-edited database is not a traceback."""

    CORRUPTIONS = {
        "total as text": "UPDATE snapshots SET total='abc' WHERE id=2",
        "root as integer": "UPDATE snapshots SET root=12345",
        "ts as text": "UPDATE snapshots SET ts='yesterday' WHERE id=2",
        "bytes as text": "UPDATE entries SET bytes='x'",
        "path as integer": "UPDATE entries SET path=77",
    }

    def test_wrong_column_types_are_reported_not_traced(self):
        write(os.path.join(self.tree, "a/f.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        write(os.path.join(self.tree, "b/f.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        good = os.path.join(self.root, "good.sqlite")
        shutil.copy(self.db, good)
        for name, update in self.CORRUPTIONS.items():
            shutil.copy(good, self.db)
            con = sqlite3.connect(self.db)
            con.execute(update)
            con.commit()
            con.close()
            complained = 0
            for args in (["list"], ["top"], ["growth", "--min-size", "1"]):
                with self.subTest(corruption=name, args=args):
                    proc = self.cli(*args, expect_ok=False)
                    self.no_traceback(proc)
                    self.assertIn(proc.returncode, (0, 1))
                    if proc.returncode == 1:
                        complained += 1
                        self.assertIn("unexpected data", proc.stderr)
                        self.assertIn("mv ", proc.stderr)
                        self.assertNotRegex(proc.stderr, r"delete it|\brm\b")
            with self.subTest(corruption=name):
                self.assertGreaterEqual(complained, 1, "no command noticed the bad data")

    def test_the_message_names_the_database_and_never_modifies_it(self):
        write(os.path.join(self.tree, "a/f.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        con = sqlite3.connect(self.db)
        con.execute("UPDATE snapshots SET total='abc'")
        con.commit()
        con.close()
        before = digest(self.db)
        proc = self.cli("list", expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn(self.db, proc.stderr)
        self.assertEqual(digest(self.db), before)


class TestPruneScope(Base):
    """--keep applies to each directory, so one cannot push another's history out."""

    def snaps(self, root, count):
        for _ in range(count):
            self.cli("snap", root, "-q", "--min-size", "1")

    def rows(self):
        return json.loads(self.cli("--json", "list").stdout)

    def test_prune_without_a_path_keeps_the_newest_n_of_every_directory(self):
        other = os.path.join(self.root, "other")
        os.makedirs(other)
        self.snaps(other, 1)             # the oldest, and the least often snapshotted
        self.snaps(self.tree, 3)
        data = json.loads(self.cli("--json", "prune", "--keep", "3").stdout)
        self.assertEqual((data["removed"], data["kept"]), (0, 4))
        self.assertEqual(sorted({r["root"] for r in self.rows()}), sorted([other, self.tree]),
                         "one directory lost all of its history")
        data = json.loads(self.cli("--json", "prune", "--keep", "2").stdout)
        self.assertEqual((data["removed"], data["kept"], data["ids"]), (1, 3, [2]))
        by_root = {}
        for r in self.rows():
            by_root.setdefault(r["root"], []).append(r["id"])
        self.assertEqual(by_root, {other: [1], self.tree: [3, 4]})

    def test_the_text_output_says_the_limit_is_per_directory(self):
        other = os.path.join(self.root, "other")
        os.makedirs(other)
        self.snaps(other, 2)
        self.snaps(self.tree, 3)
        text = self.cli("prune", "--keep", "1").stdout
        self.assertIn("removed 3 snapshot(s), kept 2", text)
        self.assertIn("per directory", text)
        self.assertIn("per directory", self.cli("prune", "--keep", "1").stdout)
        self.assertEqual(len(self.rows()), 2)

    def test_a_single_directory_keeps_the_plain_wording(self):
        self.snaps(self.tree, 3)
        self.assertNotIn("per directory", self.cli("prune", "--keep", "1").stdout)

    def test_keep_zero_is_explicit_and_removes_everything(self):
        self.snaps(self.tree, 2)
        self.assertEqual(json.loads(self.cli("--json", "prune", "--keep", "0").stdout
                                    )["removed"], 2)
        self.assertEqual(self.rows(), [])


class TestMessages(Base):
    """The notes quote what was asked for, and the boundary is inclusive (B5)."""

    def test_duration_text_is_exact(self):
        for seconds, expected in ((129600, "36h"), (86400, "1d"), (90, "90s"), (0.5, "0.5s"),
                                  (604800, "1w"), (1209600, "2w"), (3600, "1h"), (60, "1m"),
                                  (5400, "90m"), (59, "59s"), (172800, "2d"),
                                  (g.parse_duration("1.5d"), "36h")):
            with self.subTest(seconds=seconds):
                self.assertEqual(g.duration_text(seconds), expected)

    def test_the_fallback_note_names_the_duration_that_was_asked_for(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        for _ in range(2):
            self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        con = sqlite3.connect(self.db)          # a history shorter than any --since below
        con.execute("UPDATE snapshots SET ts = ? WHERE id = 1", (time.time() - 0.2,))
        con.execute("UPDATE snapshots SET ts = ? WHERE id = 2", (time.time(),))
        con.commit()
        con.close()
        for since, said in (("36h", "36h old"), ("90s", "90s old"), ("2w", "2w old"),
                            ("5s", "5s old")):
            with self.subTest(since=since):
                proc = self.cli("growth", "--since", since, "--min-size", "1")
                self.assertIn(f"no snapshot is {said} yet", proc.stderr)

    def pair_database(self, stamps):
        db = g._empty_db()
        self.addCleanup(db.close)
        for ts in stamps:
            db.execute("INSERT INTO snapshots (ts, root, total, files, dirs) "
                       "VALUES (?, ?, 1, 1, 1)", (ts, g.enc("/r")))
        return db

    def test_a_snapshot_exactly_since_older_than_the_latest_is_the_one_chosen(self):
        db = self.pair_database([100.0, 200.0, 300.0])
        first, latest, fell_back = g.pick_pair(db, "/r", 100.0, None, None)
        self.assertEqual((first["id"], latest["id"], fell_back), (2, 3, False))
        first, _, fell_back = g.pick_pair(db, "/r", 100.5, None, None)
        self.assertEqual((first["id"], fell_back), (1, False))
        first, _, fell_back = g.pick_pair(db, "/r", 99.5, None, None)
        self.assertEqual((first["id"], fell_back), (2, False))
        first, _, fell_back = g.pick_pair(db, "/r", 200.0, None, None)
        self.assertEqual((first["id"], fell_back), (1, False))
        first, _, fell_back = g.pick_pair(db, "/r", 300.5, None, None)
        self.assertEqual((first["id"], fell_back), (1, True))

    def test_a_since_that_is_exactly_the_history_is_not_a_fallback(self):
        db = self.pair_database([1000.0, 1000.0 + 86400])
        first, _, fell_back = g.pick_pair(db, "/r", 86400.0, None, None)
        self.assertEqual((first["id"], fell_back), (1, False))


class TestInitialisationDetails(Base):
    """The WAL switch happens only when needed (B1)."""

    class Recorder:
        def __init__(self, db):
            self._db = db
            self.statements = []

        def execute(self, sql, *rest):
            self.statements.append(sql)
            return self._db.execute(sql, *rest)

        def __getattr__(self, name):
            return getattr(self._db, name)

    def test_no_journal_mode_switch_when_the_database_is_already_wal(self):
        self.cli("snap", self.tree, "-q")
        db = g._open(self.db)
        self.addCleanup(db.close)
        self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        recorder = self.Recorder(db)
        g._initialise(recorder, self.db)
        switches = [s for s in recorder.statements
                    if re.search(r"journal_mode\s*=", s, re.I)]
        self.assertEqual(switches, [], "switched journal_mode on a database already in WAL")

    def test_a_fresh_database_is_switched_to_wal_exactly_once(self):
        db = g._open(self.db)
        self.addCleanup(db.close)
        recorder = self.Recorder(db)
        g._initialise(recorder, self.db)
        switches = [s for s in recorder.statements
                    if re.search(r"journal_mode\s*=\s*WAL", s, re.I)]
        self.assertEqual(len(switches), 1)
        self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_the_schema_is_checked_before_the_switch(self):
        con = sqlite3.connect(self.db)
        con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        con.execute("INSERT INTO meta VALUES ('schema', '99')")
        con.commit()
        con.close()
        db = g._open(self.db)
        self.addCleanup(db.close)
        recorder = self.Recorder(db)
        with self.assertRaises(SystemExit):
            g._initialise(recorder, self.db)
        self.assertFalse([s for s in recorder.statements if "journal_mode=" in s.lower()])

    def test_a_directory_name_sqlite_cannot_hold_is_explained(self):
        """ensure_db_dir's ValueError branch: a NUL byte in the directory."""
        for explicit in (True, False):
            with self.subTest(explicit=explicit):
                with self.assertRaises(SystemExit) as caught:
                    g.ensure_db_dir("bad\0dir/x.db", explicit)
                text = str(caught.exception)
                self.assertIn("cannot create database directory", text)
                self.assertIn("--db", text)

    def test_the_tests_never_touch_the_real_database(self):
        """Base points HOME and XDG_DATA_HOME at the temp root, so a regression that
        ignores --db writes there instead of into the developer's own history."""
        self.assertTrue(g.data_dir().startswith(self.root), g.data_dir())
        with mock.patch.dict(os.environ):
            os.environ.pop("XDG_DATA_HOME")
            self.assertTrue(g.data_dir().startswith(self.root), g.data_dir())


# --------------------------------------------------------------------------- #
# round five: what the third round of reviewers found
# --------------------------------------------------------------------------- #

class TestSinceFloatResolution(Base):
    """--since smaller than a timestamp's resolution compared a snapshot with itself."""

    def test_a_tiny_since_never_picks_the_latest_snapshot_as_the_older_one(self):
        db = g._empty_db()
        self.addCleanup(db.close)
        for ts in (1.7e9, 1.7e9 + 10):
            db.execute("INSERT INTO snapshots (ts, root, total, files, dirs) "
                       "VALUES (?, ?, 1, 1, 1)", (ts, g.enc("/r")))
        latest_ts = 1.7e9 + 10
        self.assertEqual(latest_ts - 1e-10, latest_ts, "the premise: 1e-10s moves nothing")
        first, latest, fell_back = g.pick_pair(db, "/r", 1e-10, None, None)
        self.assertEqual((first["id"], latest["id"], fell_back), (1, 2, False))

    def test_a_tiny_since_on_the_command_line_compares_two_different_snapshots(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        write(os.path.join(self.tree, "b.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        proc = self.cli("--json", "growth", "--since", "0.0000000001s", "--min-size", "1")
        data = json.loads(proc.stdout)
        self.assertEqual((data["from"]["id"], data["to"]["id"]), (1, 2))
        self.assertEqual(data["net"], 1048576)
        self.assertEqual(proc.stderr, "", "a snapshot exists, so there is no fallback")


class TestInvariantsAndBoundaries(Base):
    """The root entry is always recorded; two comparisons are strict (section 4)."""

    def test_the_root_is_recorded_even_when_it_is_smaller_than_min_size(self):
        write(os.path.join(self.tree, "a/small.bin"), 1000)
        res = g.scan(self.tree, apparent=True, min_size=1 << 30)
        self.assertGreater(res.total, 0)
        self.assertEqual(res.sizes, {self.tree: res.total})
        self.assertEqual(res.counts[self.tree], res.files)
        out = json.loads(self.cli("--json", "snap", self.tree, "--min-size", "1G").stdout)
        self.assertEqual(out["dirs"], 1)
        top = json.loads(self.cli("--json", "top").stdout)
        self.assertEqual([r["path"] for r in top], [self.tree])

    def test_a_change_of_exactly_the_threshold_is_not_reported(self):
        before, after = {"/a": 100}, {"/a": 110}
        self.assertEqual(g.diff(before, after, threshold=10), [])
        self.assertEqual([c.path for c in g.diff(before, after, threshold=9)], ["/a"])
        self.assertEqual(g.diff(after, before, threshold=10), [])      # and shrinking

    def test_the_default_threshold_line_says_more_than(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent")
        self.cli("snap", self.tree, "-q", "--apparent")
        out = self.cli("growth").stdout
        self.assertIn("nothing changed by more than 1.0M", out)

    def changes(self, child):
        return [g.Change("/p", 0, 100), g.Change("/p/c", 0, child)]

    def test_a_child_explaining_exactly_the_fraction_hides_the_parent(self):
        """blame keeps a parent only while no child explains `explain` of its change."""
        self.assertEqual([c.path for c in g.blame(self.changes(50), explain=0.5)], ["/p/c"])
        self.assertEqual([c.path for c in g.blame(self.changes(49), explain=0.5)],
                         ["/p", "/p/c"])
        self.assertEqual([c.path for c in g.blame(self.changes(51), explain=0.5)], ["/p/c"])


class TestListAcrossRoots(Base):
    """`grew list` with several roots in one database (a KeyError once regressed here)."""

    def test_list_without_a_path_shows_a_delta_only_within_the_same_root(self):
        other = os.path.join(self.root, "other")
        write(os.path.join(self.tree, "a.bin"), 1048576)
        write(os.path.join(other, "b.bin"), 2097152)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")      # 1
        self.cli("snap", other, "-q", "--apparent", "--min-size", "1")          # 2
        write(os.path.join(self.tree, "c.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")      # 3
        rows = json.loads(self.cli("--json", "list").stdout)
        self.assertEqual([(r["id"], r["root"]) for r in rows],
                         [(1, self.tree), (2, other), (3, self.tree)])
        lines = {int(m.group(1)): m.group(0) for m in
                 re.finditer(r"^\s+(\d+)\s.*$", self.cli("list").stdout, re.M)}
        self.assertEqual(set(lines), {1, 2, 3})
        self.assertNotIn("+", lines[1])
        self.assertNotIn("+", lines[2], "the first snapshot of a root has nothing to compare")
        self.assertTrue(lines[3].rstrip().endswith("+1.0M"), lines[3])
        self.assertIn(self.tree, lines[3])

    def test_snapshots_are_ordered_by_time_then_id(self):
        db = g._empty_db()
        self.addCleanup(db.close)
        for snap_id in (5, 2, 9, 3):                  # inserted out of order, same instant
            db.execute("INSERT INTO snapshots (id, ts, root, total, files, dirs) "
                       "VALUES (?, 100.0, ?, 1, 1, 1)", (snap_id, g.enc("/r")))
        self.assertEqual([r["id"] for r in g.snapshots_for(db, None)], [2, 3, 5, 9])
        self.assertEqual([r["id"] for r in g.snapshots_for(db, "/r")], [2, 3, 5, 9])

    def test_prune_reports_the_removed_ids_in_ascending_order(self):
        other = os.path.join(self.root, "other")
        os.makedirs(other)
        for folder in (self.tree, other, self.tree, other, self.tree):
            self.cli("snap", folder, "-q", "--min-size", "1")
        data = json.loads(self.cli("--json", "prune", "--keep", "1").stdout)
        self.assertEqual(data["ids"], [1, 2, 3])
        self.assertEqual(data["removed"], 3)

    def test_the_summary_hints_at_growth_only_once_there_is_something_to_compare(self):
        self.assertNotIn("compare with: grew growth", self.cli("snap", self.tree).stdout)
        self.assertIn("compare with: grew growth", self.cli("snap", self.tree).stdout)


class TestOutputToClosedPipes(Base):
    """A reader that goes away is not an error (the README promises SIGPIPE handling)."""

    def test_top_into_a_closed_pipe_exits_zero_with_nothing_on_stderr(self):
        for i in range(120):
            write(os.path.join(self.tree, f"d{i:03}", "f.bin"), 1000)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        for args in (["top", "-n", "500"], ["list"]):
            with self.subTest(args=args):
                proc = subprocess.Popen([sys.executable, GREW, "--db", self.db, *args],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                proc.stdout.close()           # the reader has gone before the first write
                _, err = proc.communicate(timeout=60)
                self.assertEqual(proc.returncode, 0, err)
                self.assertEqual(err, b"", "a closed pipe produced a message")

    def test_snap_into_a_closed_pipe_says_nothing_about_an_unwritten_summary(self):
        proc = subprocess.Popen([sys.executable, GREW, "--db", self.db, "snap", self.tree,
                                 "--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.stdout.close()
        _, err = proc.communicate(timeout=60)
        self.assertEqual(proc.returncode, 0, err)
        self.assertNotIn(b"could not be written", err)
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 1)

    def test_snap_with_both_streams_full_still_exits_zero(self):
        if not os.path.exists("/dev/full"):
            self.skipTest("no /dev/full")
        with open("/dev/full", "w") as full:
            proc = subprocess.run([sys.executable, GREW, "--db", self.db, "--json", "snap",
                                   self.tree, "-q"], stdout=full, stderr=full)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 1)

    def test_prune_to_a_full_stdout_still_succeeds_because_the_rows_are_gone(self):
        if not os.path.exists("/dev/full"):
            self.skipTest("no /dev/full")
        for _ in range(3):
            self.cli("snap", self.tree, "-q")
        with open("/dev/full", "w") as full:
            proc = subprocess.run([sys.executable, GREW, "--db", self.db, "prune",
                                   "--keep", "1"], stdout=full, stderr=subprocess.PIPE,
                                  text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("prune was done", proc.stderr)
        self.no_traceback(proc)
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 1)

    def test_growth_with_a_full_stderr_still_prints_its_report(self):
        if not os.path.exists("/dev/full"):
            self.skipTest("no /dev/full")
        write(os.path.join(self.tree, "a.bin"), 1048576)
        for _ in range(2):
            self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        with open("/dev/full", "w") as full:
            proc = subprocess.run([sys.executable, GREW, "--db", self.db, "growth",
                                   "--since", "52w", "--min-size", "1"],
                                  stdout=subprocess.PIPE, stderr=full, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("#1", proc.stdout)         # the fallback note was only a courtesy

    def closed_stderr(self, *args):
        """grew with file descriptor 2 closed, so sys.stderr is None."""
        return subprocess.run(
            ["sh", "-c", 'exec "$0" "$@" 2>&-', sys.executable, GREW, "--db", self.db, *args],
            stdout=subprocess.PIPE, text=True, errors="surrogateescape")

    def test_a_closed_stderr_never_sends_notes_into_json_on_stdout(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        for _ in range(2):
            self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        proc = self.closed_stderr("--json", "growth", "--since", "52w", "--min-size", "1")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["from"]["id"], 1)       # still pure JSON
        proc = self.closed_stderr("--json", "snap", self.tree, "--min-size", "1")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["id"], 3)       # no "scanning ..." first

    def test_note_does_nothing_without_a_stderr(self):
        out = io.StringIO()
        with mock.patch.object(g.sys, "stderr", None), contextlib.redirect_stdout(out):
            g.note("a courtesy")
        self.assertEqual(out.getvalue(), "")


class TestFailedVacuumAndPaths(Base):
    """-q means quiet even when VACUUM fails; messages name the absolute path (C1, C3)."""

    def test_prune_quiet_prints_nothing_even_when_vacuum_fails(self):
        for _ in range(3):
            self.cli("snap", self.tree, "-q")

        class NoVacuum:
            def __init__(self, db):
                self._db = db

            def execute(self, sql, *rest):
                if sql.strip().upper() == "VACUUM":
                    raise sqlite3.OperationalError("database is locked")
                return self._db.execute(sql, *rest)

            def __getattr__(self, name):
                return getattr(self._db, name)

        real_connect = g.connect
        with mock.patch.object(g, "connect",
                               lambda *a, **k: NoVacuum(real_connect(*a, **k))):
            proc = self.cli("prune", "--keep", "1", "-q")
        self.assertEqual((proc.stdout, proc.stderr), ("", ""))
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 1)

    def test_a_relative_path_is_named_by_its_absolute_form(self):
        self.cli("snap", self.tree, "-q")
        previous = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        shown = os.path.abspath("nowhere/at/all")
        for args in (["top", "nowhere/at/all"], ["list", "nowhere/at/all"],
                     ["growth", "nowhere/at/all"]):
            with self.subTest(args=args):
                proc = self.cli(*args, expect_ok=False)
                text = proc.stdout + proc.stderr
                self.assertIn(shown, text)
                self.assertIn(f"grew snap {shown}", text)


class TestErrorClassification(Base):
    """failure_kind decides which advice is given; each cause has its own words."""

    def test_every_cause_is_recognised(self):
        cases = {
            "database is locked": "locked",
            "database table is busy": "locked",
            "attempt to write a readonly database": "readonly",
            "unable to open database file": "readonly",
            "disk I/O error": "full",
            "database or disk is full": "full",
            "file is not a database": "corrupt",
            "database disk image is malformed": "corrupt",
            "no such table: entries": "corrupt",
            "no such column: bytes": "corrupt",
            "file is not a grew database: it has tables": "foreign",
            "something nobody has seen": "other",
        }
        for message, kind in cases.items():
            with self.subTest(message=message):
                self.assertEqual(g.failure_kind(sqlite3.DatabaseError(message)), kind)

    def test_a_database_in_a_directory_that_cannot_be_searched_is_explained(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        folder = os.path.join(self.root, "locked")
        os.makedirs(folder)
        made_read_only(self, folder)
        os.chmod(folder, 0)
        db = os.path.join(folder, "x.db")
        for command in ("list", "snap"):
            with self.subTest(command=command):
                proc = run_main("--db", db, command, *([self.tree, "-q"] if command == "snap"
                                                       else []))
                self.assertEqual(proc.returncode, 1)
                self.no_traceback(proc)
                self.assertIn("cannot access database", proc.stderr)
                self.assertIn("permissions", proc.stderr)
                self.assertNotIn("delete", proc.stderr)
                self.assertNotIn("corrupt", proc.stderr)


class TestSchemaVersionBoundary(Base):
    """A database from the next schema is refused untouched, not just from a far one."""

    def test_the_next_schema_version_is_refused_before_anything_is_written(self):
        for version in (g.SCHEMA_VERSION + 1, g.SCHEMA_VERSION + 6, 99):
            with self.subTest(version=version):
                if os.path.exists(self.db):
                    os.remove(self.db)
                con = sqlite3.connect(self.db)
                con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
                con.execute("INSERT INTO meta VALUES ('schema', ?)", (str(version),))
                con.commit()
                con.close()
                before = digest(self.db)
                for args in (["list"], ["snap", self.tree, "-q"], ["prune"]):
                    proc = self.cli(*args, expect_ok=False)
                    self.assertEqual(proc.returncode, 1)
                    self.assertIn(f"schema v{version}", proc.stderr)
                self.assertEqual(digest(self.db), before)
                self.assertEqual(sorted(os.listdir(self.root)),
                                 sorted(["db.sqlite", "tree"]))

    def test_the_current_schema_version_is_accepted(self):
        self.cli("snap", self.tree, "-q")
        self.cli("list")


class TestReaderConnections(Base):
    """Which connection a reader takes (B2): never write-capable when it need not be."""

    def record_opens(self):
        opened = []
        real = g._open

        def spy(target, **kwargs):
            opened.append((target, kwargs.get("uri", False)))
            return real(target, **kwargs)

        return opened, mock.patch.object(g, "_open", spy)

    def test_a_writable_database_is_read_with_an_ordinary_connection(self):
        """immutable=1 would miss a writer that checkpoints between the checks."""
        self.cli("snap", self.tree, "-q")
        opened, spy = self.record_opens()
        with spy:
            db = g.connect(self.db, readonly=True)
        db.close()
        self.assertEqual(opened, [(self.db, False)])

    def test_a_read_only_file_is_read_without_creating_anything(self):
        if os.geteuid() == 0:
            self.skipTest("root can write to a read-only file")
        self.cli("snap", self.tree, "-q")
        made_read_only(self, self.db)
        opened, spy = self.record_opens()
        with spy:
            db = g.connect(self.db, readonly=True)
        db.close()
        self.assertEqual(len(opened), 1)
        self.assertTrue(opened[0][1], "a URI connection was expected")
        self.assertIn("immutable=1", opened[0][0])


class TestInitialiseRetries(Base):
    """The retry loop in _initialise waits, and leaves no transaction open."""

    def test_each_retry_waits_a_moment_instead_of_spinning(self):
        real = sqlite3.connect(":memory:")
        real.row_factory = sqlite3.Row
        self.addCleanup(real.close)
        state = {"left": 3}

        class Busy:
            def execute(self, sql, *rest):
                if "BEGIN IMMEDIATE" in sql and state["left"] > 0:
                    state["left"] -= 1
                    raise sqlite3.OperationalError("database is locked")
                return real.execute(sql, *rest)

            def __getattr__(self, name):
                return getattr(real, name)

        with mock.patch.object(g.time, "sleep") as sleep:
            g._initialise(Busy(), "x")
        self.assertEqual(sleep.call_count, 3)
        for call in sleep.call_args_list:
            self.assertTrue(0 < call.args[0] <= 0.5, call)

    def test_a_failure_after_the_transaction_began_is_rolled_back_before_the_retry(self):
        """Without the rollback, the retry's BEGIN says 'cannot start a transaction within
        a transaction' and the whole start-up fails, though the lock was transient."""
        real = sqlite3.connect(":memory:")
        real.row_factory = sqlite3.Row
        self.addCleanup(real.close)
        state = {"left": 2}

        class LockedMidway:
            def execute(self, sql, *rest):
                if "CREATE TABLE" in sql and state["left"] > 0:
                    state["left"] -= 1
                    raise sqlite3.OperationalError("database is locked")   # still in BEGIN
                return real.execute(sql, *rest)

            def __getattr__(self, name):
                return getattr(real, name)

        with mock.patch.object(g.time, "sleep"):
            g._initialise(LockedMidway(), "x")
        self.assertEqual(state["left"], 0)
        self.assertFalse(real.in_transaction)
        tables = {r[0] for r in real.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"meta", "snapshots", "entries"} <= tables)


class TestWritableCheckRace(Base):
    """_check_writable ran into a racing grew deleting its -wal: access() said no (found
    by repeating the stampede tests; 1 run in about 30)."""

    def test_a_sidecar_that_vanishes_between_the_checks_is_not_called_read_only(self):
        seen = {}

        def lexists(candidate):
            seen[candidate] = seen.get(candidate, 0) + 1
            return seen[candidate] == 1          # there, and then gone

        with mock.patch.object(g.os.path, "lexists", lexists), \
                mock.patch.object(g.os, "access", lambda *a, **k: False):
            g._check_writable(self.db)           # must not exit
        self.assertEqual(sorted(seen), sorted([self.db, self.db + "-wal", self.db + "-shm"]))

    def test_a_sidecar_that_stays_and_is_unwritable_is_still_refused(self):
        with mock.patch.object(g.os.path, "lexists", lambda candidate: True), \
                mock.patch.object(g.os, "access", lambda *a, **k: False):
            with self.assertRaises(SystemExit) as caught:
                g._check_writable(self.db)
        self.assertIn("read-only", str(caught.exception))


class TestHardlinkedSymlinks(Base):
    """du counts a hardlinked symlink's inode once, like any non-directory."""

    def build(self):
        folder = os.path.join(self.tree, "hs")
        os.makedirs(folder)
        first = os.path.join(folder, "s0")
        os.symlink("x" * 200, first)
        for i in range(1, 6):
            try:
                os.link(first, os.path.join(folder, f"s{i}"), follow_symlinks=False)
            except (NotImplementedError, OSError):
                self.skipTest("this platform cannot hardlink a symlink")
        if os.lstat(first).st_nlink != 6:
            self.skipTest("hardlinking a symlink made a copy here")

    def test_six_names_for_one_symlink_are_counted_once(self):
        self.build()
        res = g.scan(self.tree, apparent=True, min_size=0)
        self.assertEqual(res.total, 200)
        self.assertEqual(res.files, 1)
        self.assertEqual(res.total, apparent_bytes(self.tree))

    def test_allocated_total_matches_du_with_hardlinked_symlinks(self):
        self.build()
        self.assertEqual(g.scan(self.tree, min_size=0).total, du_bytes(self.tree))

    def test_matches_gnu_du_apparent_size_when_available(self):
        self.build()
        proc = subprocess.run(["du", "-s", "--apparent-size", "--block-size=1", self.tree],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            self.skipTest("this du has no --apparent-size or --block-size")
        self.assertEqual(g.scan(self.tree, apparent=True, min_size=0).total,
                         int(proc.stdout.split()[0]))


class TestSnapPaths(Base):
    """snap names the real cause when it cannot use a path (other)."""

    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        super().setUp()

    def test_a_directory_behind_one_that_cannot_be_searched_is_a_permission_problem(self):
        folder = os.path.join(self.root, "un")
        os.makedirs(os.path.join(folder, "x"))
        made_read_only(self, folder)
        os.chmod(folder, 0)
        proc = self.cli("snap", os.path.join(folder, "x"), "-q", expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.no_traceback(proc)
        self.assertIn("permission denied", proc.stderr)
        self.assertNotIn("not a directory", proc.stderr)

    def test_a_directory_that_cannot_be_listed_is_counted_and_the_snapshot_succeeds(self):
        folder = os.path.join(self.tree, "un")
        os.makedirs(folder)
        made_read_only(self, folder)
        os.chmod(folder, 0)
        out = json.loads(self.cli("--json", "snap", folder).stdout)
        self.assertEqual((out["errors"], out["total"]), (1, 0))

    def test_a_missing_path_and_a_file_are_both_not_a_directory(self):
        write(os.path.join(self.tree, "f.bin"), 10)
        for path in (os.path.join(self.tree, "ghost"), os.path.join(self.tree, "f.bin"),
                     os.path.join(self.tree, "f.bin", "below")):
            with self.subTest(path=path):
                proc = self.cli("snap", path, expect_ok=False)
                self.assertEqual(proc.returncode, 1)
                self.assertIn("not a directory", proc.stderr)


class TestMemoryDatabaseName(Base):
    """--db :memory: used to report a snapshot and keep nothing."""

    def test_it_is_refused_for_every_command_with_the_way_out(self):
        for args in (["snap", self.tree], ["list"], ["top"], ["growth"], ["prune"]):
            with self.subTest(args=args):
                proc = run_main("--db", ":memory:", *args)
                self.assertEqual(proc.returncode, 1)
                self.assertIn("./:memory:", proc.stderr)
                self.no_traceback(proc)
                self.assertNotIn("snapshot #", proc.stdout)

    def test_a_file_called_memory_works_when_written_as_a_path(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        previous = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        run_main("--db", "./:memory:", "snap", self.tree, "-q", "--min-size", "1")
        self.assertTrue(os.path.exists(os.path.join(self.root, ":memory:")))
        listed = json.loads(run_main("--db", "./:memory:", "--json", "list").stdout)
        self.assertEqual(len(listed), 1)


class TestFailedWriteToReadOnlyDatabase(Base):
    """A write that cannot succeed must not leave -wal and -shm that outlive the fix (B2)."""

    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores file permissions")
        super().setUp()
        write(os.path.join(self.tree, "a/f.bin"), 1048576)
        self.cli("snap", self.tree, "-q")
        self.cli("snap", self.tree, "-q")
        self.listing = sorted(os.listdir(self.root))

    def test_a_failed_snap_or_prune_creates_nothing_and_a_later_fix_works(self):
        made_read_only(self, self.db)
        for args in (["snap", self.tree, "-q"], ["prune", "--keep", "1", "-q"]):
            with self.subTest(args=args):
                proc = self.cli(*args, expect_ok=False)
                self.assertEqual(proc.returncode, 1)
                self.no_traceback(proc)
                self.assertIn("read-only", proc.stderr)
                self.assertIn("chmod u+w", proc.stderr)
                self.assertNotIn("delete", proc.stderr)
                self.assertNotIn("corrupt", proc.stderr)
                self.assertEqual(sorted(os.listdir(self.root)), self.listing,
                                 "the failed write left files behind")
        os.chmod(self.db, 0o644)       # what the advice says to do
        self.cli("snap", self.tree, "-q")
        self.cli("prune", "--keep", "1", "-q")
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 1)

    def test_a_read_only_leftover_beside_a_writable_database_is_named(self):
        leftover = self.db + "-shm"
        with open(leftover, "wb"):
            pass
        os.chmod(leftover, 0o444)
        proc = self.cli("snap", self.tree, "-q", expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn(leftover, proc.stderr)
        self.assertIn("the leftover file beside it", proc.stderr)
        self.assertIn("chmod u+w", proc.stderr)
        self.assertNotIn("delete", proc.stderr)
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 2)


class TestScannedTreeIsNotWritten(Base):
    """grew writes nothing outside its database, least of all into what it scans."""

    def fingerprint(self):
        found = {}
        for folder, dirs, files in os.walk(self.tree):
            for name in dirs + files:
                path = os.path.join(folder, name)
                st = os.lstat(path)
                found[path] = (st.st_mode, st.st_size, st.st_mtime_ns, st.st_ino)
            st = os.lstat(folder)
            found[folder] = (st.st_mode, st.st_mtime_ns, st.st_ino)
        return found

    def test_a_snapshot_leaves_the_scanned_tree_exactly_as_it_was(self):
        write(os.path.join(self.tree, "a/b/f.bin"), 5000)
        os.symlink("a", os.path.join(self.tree, "link"))
        os.makedirs(os.path.join(self.tree, "empty"))
        before = self.fingerprint()
        for _ in range(2):
            self.cli("snap", self.tree, "--apparent", "--min-size", "1")
        self.cli("snap", self.tree)
        self.cli("growth", "--from", "1", "--to", "2", "--min-size", "1")
        self.cli("top")
        self.cli("list")
        self.cli("prune", "--keep", "1")
        self.assertEqual(self.fingerprint(), before)
        self.assertEqual(sorted(os.listdir(self.root)), sorted(["tree", "db.sqlite"]))


# --------------------------------------------------------------------------- #
# round five: what the third round of reviewers found
# --------------------------------------------------------------------------- #

class TestGateDoesNotOrphan(unittest.TestCase):
    """A stampede child whose gate never opens must exit, not spin until reboot.

    A killed test run leaves its gate file's directory deleted, so the file can
    never appear. Fourteen such children burned 1.2 cores for two hours here.
    """

    def start(self, gate, **env):
        return subprocess.Popen([sys.executable, "-c", TestParallelStartup.GATED, GREW,
                                 gate, "list"], env=dict(os.environ, **env),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_the_gate_has_a_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.start(os.path.join(tmp, "never"), GREW_GATE_SECONDS="0.5")
            try:
                proc.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                self.fail("a child with a gate that never opens kept waiting")
            self.assertEqual(proc.returncode, 3)

    def test_a_child_exits_when_the_process_that_started_it_is_gone(self):
        if not os.path.isdir("/proc"):
            self.skipTest("no /proc to look at the child with")
        starter = (
            "import os, subprocess, sys\n"
            "env = dict(os.environ, GREW_GATE_PARENT=str(os.getpid()))\n"
            "p = subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2], sys.argv[3],"
            " 'list'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "print(p.pid, flush=True)\n")
        with tempfile.TemporaryDirectory() as tmp:
            out = subprocess.run([sys.executable, "-c", starter, TestParallelStartup.GATED,
                                  GREW, os.path.join(tmp, "never")],
                                 capture_output=True, text=True, timeout=60)
            pid = int(out.stdout.split()[0])

            def running():
                try:
                    with open(f"/proc/{pid}/stat") as f:
                        return f.read().rsplit(")", 1)[1].split()[0] != "Z"
                except OSError:
                    return False

            def reap():
                if running():
                    os.kill(pid, 9)
            self.addCleanup(reap)
            deadline = time.monotonic() + 20
            while running() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertFalse(running(), "the child outlived the process that started it")


class TestSnapOutput(Base):
    """What snap prints: nothing under -q (the cron form), and a stable JSON shape."""

    def setUp(self):
        super().setUp()
        write(os.path.join(self.tree, "a/f.bin"), 3 * 1048576)

    def test_a_quiet_snap_prints_nothing_at_all(self):
        proc = self.cli("snap", self.tree, "-q", "--min-size", "1")
        self.assertEqual((proc.stdout, proc.stderr), ("", ""))
        proc = self.cli("snap", self.tree, "-q")
        self.assertEqual((proc.stdout, proc.stderr), ("", ""))
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 2)

    def test_a_plain_snap_announces_itself_and_prints_a_summary(self):
        proc = self.cli("snap", self.tree, "--min-size", "1")
        self.assertIn("scanning", proc.stderr)
        self.assertIn("snapshot #1", proc.stdout)
        self.assertIn("across", proc.stdout)

    def test_snap_json_has_exactly_these_fields(self):
        out = json.loads(self.cli("--json", "snap", self.tree, "--min-size", "1", "-q").stdout)
        self.assertEqual(set(out), {"id", "root", "total", "files", "dirs", "errors",
                                    "elapsed"})
        self.assertEqual((out["id"], out["root"]), (1, self.tree))
        self.assertIsInstance(out["elapsed"], float)
        self.assertGreaterEqual(out["elapsed"], 0)
        self.assertEqual((out["files"], out["dirs"], out["errors"]), (1, 2, 0))
        self.assertEqual(out["total"], du_bytes(self.tree))


class TestPruneOutputDetails(Base):
    """prune's JSON fields, and its quiet handling of a reader that went away."""

    def setUp(self):
        super().setUp()
        write(os.path.join(self.tree, "a.bin"), 1048576)
        previous = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        for _ in range(3):
            self.cli("snap", "tree", "-q")

    def test_json_names_the_root_as_an_absolute_path_even_when_typed_relative(self):
        out = json.loads(self.cli("--json", "prune", "tree", "--keep", "1").stdout)
        self.assertEqual(out["root"], os.path.abspath("tree"))
        self.assertTrue(os.path.isabs(out["root"]))
        self.assertEqual((out["removed"], out["kept"], out["keep"]), (2, 1, 1))
        self.assertEqual(out["ids"], [1, 2])
        out = json.loads(self.cli("--json", "prune", "--keep", "5").stdout)
        self.assertIsNone(out["root"])
        self.assertEqual(set(out), {"root", "removed", "ids", "kept", "keep", "reclaimed"})

    def failing_vacuum(self):
        class NoVacuum:
            def __init__(self, db):
                self._db = db

            def execute(self, sql, *rest):
                if sql.strip().upper() == "VACUUM":
                    raise sqlite3.OperationalError("database is locked")
                return self._db.execute(sql, *rest)

            def __getattr__(self, name):
                return getattr(self._db, name)

        real_connect = g.connect
        return mock.patch.object(g, "connect", lambda *a, **k: NoVacuum(real_connect(*a, **k)))

    def test_json_says_the_space_was_not_reclaimed_when_vacuum_failed(self):
        with self.failing_vacuum():
            failed = json.loads(self.cli("--json", "prune", "--keep", "2").stdout)
        self.assertEqual(failed["removed"], 1)
        self.assertIs(failed["reclaimed"], False)
        worked = json.loads(self.cli("--json", "prune", "--keep", "1").stdout)
        self.assertEqual(worked["removed"], 1)
        self.assertIs(worked["reclaimed"], True)

    def test_prune_into_a_closed_pipe_ends_quietly_like_every_other_command(self):
        proc = subprocess.Popen([sys.executable, GREW, "--db", self.db, "prune", "--keep", "1"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.stdout.close()
        _, err = proc.communicate(timeout=60)
        self.assertEqual(proc.returncode, 0, err)
        self.assertEqual(err, b"", "a closed pipe produced a message")
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 1)


class TestTwoHardlinkedInodes(Base):
    """Two different multiply-linked inodes are two inodes, not one."""

    def link(self, folder, name, size, kind):
        first = os.path.join(folder, name + "0")
        if kind == "symlink":
            os.symlink("x" * size, first)
        else:
            write(first, size)
        try:
            os.link(first, os.path.join(folder, name + "1"), follow_symlinks=False)
        except (NotImplementedError, OSError):
            self.skipTest("this platform cannot make that hardlink")
        if os.lstat(first).st_nlink != 2:
            self.skipTest("hardlinking made a copy here")

    def test_two_hardlinked_symlinks_are_counted_once_each(self):
        folder = os.path.join(self.tree, "hs")
        os.makedirs(folder)
        self.link(folder, "a", 200, "symlink")
        self.link(folder, "b", 300, "symlink")
        res = g.scan(self.tree, apparent=True, min_size=0)
        self.assertEqual((res.total, res.files), (500, 2))
        self.assertEqual(res.total, apparent_bytes(self.tree))

    def test_two_hardlinked_files_are_counted_once_each(self):
        folder = os.path.join(self.tree, "hf")
        os.makedirs(folder)
        self.link(folder, "a", 1000, "file")
        self.link(folder, "b", 2000, "file")
        res = g.scan(self.tree, apparent=True, min_size=0)
        self.assertEqual((res.total, res.files), (3000, 2))
        self.assertEqual(g.scan(self.tree, min_size=0).total, du_bytes(self.tree))


class TestSmallPins(Base):
    """Behaviour and wording that a mutation run showed nothing was holding."""

    def test_the_busy_timeout_is_generous_enough_for_a_stampede(self):
        self.assertGreaterEqual(g.BUSY_SECONDS, 10)

    def test_failure_kind_knows_a_full_disk_in_every_wording(self):
        for text in ("database or disk is full", "disk I/O error",
                     "No space left on device"):
            with self.subTest(text=text):
                self.assertEqual(g.failure_kind(sqlite3.OperationalError(text)), "full")

    def test_a_database_with_snapshots_but_no_entries_table_reads_as_empty(self):
        con = sqlite3.connect(self.db)
        con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        con.execute("INSERT INTO meta VALUES ('schema', '1')")
        con.execute("CREATE TABLE snapshots (id INTEGER PRIMARY KEY, ts REAL, root BLOB,"
                    " total INTEGER, files INTEGER, dirs INTEGER, errors INTEGER,"
                    " elapsed REAL, apparent INTEGER)")
        con.execute("INSERT INTO snapshots VALUES (1, 1.0, x'2f', 5, 1, 1, 0, 0.1, 0)")
        con.commit()
        con.close()
        proc = self.cli("top", expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no snapshots yet", proc.stderr)
        self.assertNotIn("corrupt", proc.stderr)
        self.no_traceback(proc)

    def test_a_hand_edited_non_numeric_schema_value_is_not_a_crash(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q")
        con = sqlite3.connect(self.db)
        con.execute("UPDATE meta SET value='abc' WHERE key='schema'")
        con.commit()
        con.close()
        for args in (["list"], ["snap", self.tree, "-q"]):
            with self.subTest(args=args):
                proc = self.cli(*args, expect_ok=False)
                self.no_traceback(proc)
                self.assertNotIn("delete", proc.stderr)
                self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_a_missing_snap_path_says_it_does_not_exist(self):
        proc = self.cli("snap", os.path.join(self.tree, "ghost"), expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("it does not exist", proc.stderr)

    def test_a_tied_ordering_is_not_a_hash_accident(self):
        # 60 paths with the same change: set order differs between runs, so
        # only an explicit tie-break gives one answer.
        before = {f"/r/d{i:02}": 0 for i in range(60)}
        after = {path: 5000 for path in before}
        shuffled = list(after.items())
        random.Random(3).shuffle(shuffled)
        got = [c.path for c in g.diff(before, dict(shuffled))]
        self.assertEqual(got, sorted(after))


class TestForeignMetaTable(Base):
    """A table called `meta` does not make a database grew's (it is a common name)."""

    def foreign(self, name, *statements):
        path = os.path.join(self.root, name)
        con = sqlite3.connect(path)
        for statement in statements:
            con.execute(statement)
        con.commit()
        con.close()
        return path

    def test_other_programs_databases_with_a_meta_table_are_refused_untouched(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        cases = {
            "key-value-plus-other-table": [
                "CREATE TABLE meta(key, value)", "CREATE TABLE other(a)"],
            "key-value-with-someone-elses-row": [
                "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)",
                "INSERT INTO meta VALUES ('app', 'other')", "CREATE TABLE x(a)"],
            "three-columns": [
                "CREATE TABLE meta(k, v, x)", "CREATE TABLE other(a)"],
            "schema-row-but-foreign-tables": [
                "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)",
                "INSERT INTO meta VALUES ('schema', '1')", "CREATE TABLE other(a)"],
            "tables-with-an-empty-meta": [
                "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)",
                "CREATE TABLE other(a)"],
        }
        for name, statements in cases.items():
            path = self.foreign(name + ".sqlite", *statements)
            before = digest(path)
            for args in (["snap", self.tree, "-q"], ["list"], ["top"], ["prune", "-q"]):
                with self.subTest(case=name, args=args):
                    proc = run_main("--db", path, *args)
                    self.assertEqual(proc.returncode, 1, proc.stdout)
                    self.assertIn("another program's", proc.stderr)
                    self.assertNotIn("delete", proc.stderr)
                    self.assertNotIn("corrupt", proc.stderr)
                    self.no_traceback(proc)
                    self.assertEqual(digest(path), before, "the foreign file was written to")
            self.assertEqual(sorted(f for f in os.listdir(self.root) if name in f),
                             [name + ".sqlite"], "sidecar files appeared")

    def test_grews_own_database_and_a_bare_meta_are_still_accepted(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q")
        self.cli("snap", self.tree, "-q")
        self.assertEqual(len(json.loads(self.cli("--json", "list").stdout)), 2)
        bare = self.foreign("bare.sqlite", "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
        self.assertEqual(run_main("--db", bare, "list").returncode, 0)
        self.assertEqual(run_main("--db", bare, "snap", self.tree, "-q").returncode, 0)


class TestSecondInterrupt(Base):
    """A second Ctrl-C while the first is being handled is still just "interrupted"."""

    def test_main_survives_an_interrupt_during_the_interrupt_message(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        try:
            with mock.patch.object(g, "scan", side_effect=KeyboardInterrupt), \
                    mock.patch.object(g, "note", side_effect=KeyboardInterrupt):
                code = g.main(["--db", self.db, "snap", self.tree, "-q"])
        except KeyboardInterrupt:
            self.fail("a second Ctrl-C escaped main() as a traceback")
        self.assertEqual(code, 130)

    def test_entry_turns_an_escaping_interrupt_into_130(self):
        with mock.patch.object(g, "main", side_effect=KeyboardInterrupt):
            try:
                code = g.entry()
            except KeyboardInterrupt:
                self.fail("entry() let an interrupt escape")
        self.assertEqual(code, 130)


class TestMountedReadOnly(Base):
    """A read-only mount is not cured by chmod, so the advice must not say so."""

    def refuse_write_access(self):
        real = os.access
        return mock.patch.object(
            g.os, "access", lambda p, mode, **k: False if mode == os.W_OK else real(p, mode, **k))

    def setUp(self):
        super().setUp()
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q")
        self.listing = sorted(os.listdir(self.root))

    def test_snap_and_prune_blame_the_mount_not_the_permissions(self):
        for args in (["snap", self.tree, "-q"], ["prune", "--keep", "0", "-q"]):
            with self.subTest(args=args):
                with self.refuse_write_access(), \
                        mock.patch.object(g, "mounted_read_only", return_value=True):
                    proc = self.cli(*args, expect_ok=False)
                self.assertEqual(proc.returncode, 1)
                self.no_traceback(proc)
                self.assertIn("mounted read-only", proc.stderr)
                self.assertNotIn("chmod", proc.stderr)
                self.assertNotIn("delete", proc.stderr)
                self.assertEqual(sorted(os.listdir(self.root)), self.listing)

    def test_a_file_that_is_merely_read_only_still_gets_the_chmod_advice(self):
        with self.refuse_write_access(), \
                mock.patch.object(g, "mounted_read_only", return_value=False):
            proc = self.cli("snap", self.tree, "-q", expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("chmod u+w", proc.stderr)
        self.assertNotIn("mounted read-only", proc.stderr)

    def test_mounted_read_only_reads_the_filesystem_flags(self):
        self.assertFalse(g.mounted_read_only(self.db))
        flagged = types.SimpleNamespace(f_flag=os.ST_RDONLY | 4)
        with mock.patch.object(g.os, "statvfs", return_value=flagged):
            self.assertTrue(g.mounted_read_only(self.db))
        with mock.patch.object(g.os, "statvfs", return_value=types.SimpleNamespace(f_flag=4)):
            self.assertFalse(g.mounted_read_only(self.db))
        with mock.patch.object(g.os, "statvfs", side_effect=OSError("gone")):
            self.assertFalse(g.mounted_read_only(self.db))

    def test_a_new_database_on_a_read_only_mount_names_the_mount(self):
        target = os.path.join(self.root, "new.sqlite")
        refused = OSError(errno.EROFS, "Read-only file system")
        with mock.patch.object(g.os, "open", side_effect=refused):
            proc = run_main("--db", target, "snap", self.tree, "-q")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("mounted read-only", proc.stderr)
        self.assertNotIn("delete", proc.stderr)
        self.no_traceback(proc)


class TestSizeLimitedReaders(Base):
    """A process with a file-size limit cannot create -wal and -shm, but can still read."""

    def test_listing_works_under_a_zero_file_size_limit(self):
        try:
            import resource
        except ImportError:
            self.skipTest("no resource module")
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q")

        def limit():
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))

        for args in (["list"], ["top"]):
            with self.subTest(args=args):
                proc = subprocess.run([sys.executable, GREW, "--db", self.db, *args],
                                      capture_output=True, text=True, preexec_fn=limit,
                                      timeout=60)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn(self.tree, proc.stdout)
                self.assertNotIn("disk is full", proc.stderr)


class TestDatabaseNamedInMessages(Base):
    """A mistyped --db must not read like a first run (it names the file it looked for)."""

    def test_a_missing_database_is_named_by_every_reading_command(self):
        missing = os.path.join(self.root, "typo", "snaps.db")
        for args in (["top"], ["list"], ["growth"], ["top", self.tree], ["list", self.tree]):
            with self.subTest(args=args):
                proc = run_main("--db", missing, *args)
                self.no_traceback(proc)
                self.assertIn(missing, proc.stdout + proc.stderr)
                self.assertIn("no snapshots yet", proc.stdout + proc.stderr)
        self.assertFalse(os.path.exists(os.path.dirname(missing)), "a reader created something")

    def test_an_empty_file_is_named_too_and_a_real_database_is_not_dragged_in(self):
        empty = os.path.join(self.root, "empty.db")
        open(empty, "w").close()
        self.assertIn(empty, run_main("--db", empty, "top").stderr)
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q")
        other = os.path.join(self.root, "elsewhere")
        os.makedirs(other)
        text = self.cli("top", other, expect_ok=False).stderr
        self.assertNotIn(self.db, text)           # the database exists; the path is the problem
        self.assertIn("1 other root has snapshots", text)

    def test_the_default_database_is_named_when_it_is_missing(self):
        proc = self.with_env("top", env={}, expect_ok=False)
        self.assertIn(os.path.join(os.environ["XDG_DATA_HOME"], "grew", "snapshots.db"),
                      proc.stderr)


class TestDurationText(unittest.TestCase):
    def test_no_exponent_notation_whatever_the_size(self):
        for seconds, shown in ((1234567, "1234567s"), (90, "90s"), (0.5, "0.5s"),
                               (129600, "36h"), (86400 * 7, "1w"), (1.25, "1.25s")):
            with self.subTest(seconds=seconds):
                self.assertEqual(g.duration_text(seconds), shown)
        self.assertNotIn("e+", g.duration_text(6.048e28))

    def test_a_huge_since_is_reported_without_exponent_notation(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "d.sqlite")
            os.makedirs(os.path.join(tmp, "t"))
            write(os.path.join(tmp, "t", "f"), 2000000)
            run_main("--db", db, "snap", os.path.join(tmp, "t"), "-q", "--min-size", "1")
            run_main("--db", db, "snap", os.path.join(tmp, "t"), "-q", "--min-size", "1")
            proc = run_main("--db", db, "growth", "--since", "1234567s", "--min-size", "1")
        self.assertIn("1234567s", proc.stderr)
        self.assertNotIn("e+", proc.stderr)


class TestEscapeSequencesInNames(Base):
    """A directory name is chosen by whoever can create it; it must not drive the terminal."""

    NAMES = (b"esc\x1b[2J\x1b]0;pwned\x07x", b"nl\nFORGED output line", b"cr\rrewrite",
             "c1\u0085\u009bx".encode(), b"raw\x9bbyte", b"del\x7fx")

    def build(self):
        self.paths = []
        for name in self.NAMES:
            folder = os.path.join(os.fsencode(self.tree), name)
            try:
                os.makedirs(os.path.join(folder, b"s"))
            except OSError:
                continue            # a filesystem that refuses such a name (macOS, for bytes)
            with open(os.path.join(folder, b"s", b"f"), "wb") as f:
                f.write(b"\0" * 3000000)
            self.paths.append(os.fsdecode(folder))
        if len(self.paths) < 2 or not self.paths[0].endswith("x"):
            self.skipTest("this filesystem will not hold names with control characters")
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        for folder in self.paths:
            with open(os.path.join(os.fsencode(folder), b"s", b"g"), "wb") as f:
                f.write(b"\0" * 1000000)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")

    def assertClean(self, text, what):
        for bad in ("\x1b", "\x07", "\r", "\x7f", "\x85", "\x9b", "\udc9b"):
            self.assertNotIn(bad, text, f"{what} printed a raw control character {bad!r}")
        self.assertNotIn("\nFORGED", text, f"{what} let a name forge a line")

    def test_list_top_and_growth_escape_names(self):
        self.build()
        for args in (["list"], ["top", "-n", "50"],
                     ["growth", "--all", "-n", "50", "--min-size", "1"]):
            with self.subTest(args=args):
                self.assertClean(self.cli(*args).stdout, " ".join(args))
        shown = self.cli("top", "-n", "50").stdout
        self.assertIn("esc\\x1b[2J\\x1b]0;pwned\\x07x", shown)
        self.assertIn("nl\\x0aFORGED output line", shown)

    def test_json_still_carries_the_real_names(self):
        self.build()
        names = {c["path"] for c in json.loads(self.cli("--json", "top", "-n", "50").stdout)}
        self.assertIn(self.paths[0], names)
        self.assertIn(self.paths[1], names)

    def test_error_messages_escape_the_path_they_name(self):
        ghost = os.path.join(self.tree, "no\x1b[2Jpe\nFORGED")
        for args in (["snap", ghost], ["top", ghost], ["list", ghost], ["growth", ghost],
                     ["prune", ghost]):
            with self.subTest(args=args):
                proc = self.cli(*args, expect_ok=False)
                self.assertClean(proc.stdout + proc.stderr, " ".join(args))
        proc = subprocess.run([sys.executable, GREW, "--db", self.db, "snap", ghost],
                              capture_output=True, text=True, errors="surrogateescape")
        self.assertEqual(proc.returncode, 1)
        self.assertClean(proc.stderr, "the real command line")
        self.assertIn("no\\x1b[2Jpe\\x0aFORGED", proc.stderr)

    def test_safe_spells_out_controls_and_leaves_ordinary_text_alone(self):
        self.assertEqual(g.safe("plain / ünïcode 日本"),
                         "plain / ünïcode 日本")
        self.assertEqual(g.safe("a\x1b[0mb"), "a\\x1b[0mb")
        self.assertEqual(g.safe("a\nb\tc"), "a\\x0ab\\x09c")
        self.assertEqual(g.safe("a\nb\tc", layout=True), "a\nb\tc")
        self.assertEqual(g.safe("x\udc9by"), "x\\x9by")
        self.assertEqual(g.safe("x\udce9y"), "x\udce9y")     # a high raw byte is not a control

    def test_a_system_exit_message_cannot_drive_the_terminal_either(self):
        err = io.StringIO()
        message = "grew: bad \x1b[2J name\nnext line"
        with mock.patch.object(g, "main", side_effect=SystemExit(message)), \
                mock.patch.object(g.sys, "stderr", err):
            self.assertEqual(g.entry(), 1)
        self.assertEqual(err.getvalue(), "grew: bad \\x1b[2J name\nnext line\n")


class TestTiedGrowthIsStable(Base):
    """Equal changes print in one order, whatever the hash seed (so -n cuts the same rows)."""

    def test_growth_and_top_do_not_depend_on_string_hashing(self):
        names = ("alpha", "beta", "gamma", "delta")
        for name in names:
            write(os.path.join(self.tree, name, "f.bin"), 2000000)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        for name in names:
            write(os.path.join(self.tree, name, "g.bin"), 1000000)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        seen = set()
        for seed in ("1", "2"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            for args in (["--json", "growth", "--min-size", "1", "-n", "3"],
                         ["--json", "top", "-n", "3"]):
                seen.add((tuple(args), self.cli(*args, env=env).stdout))
        self.assertEqual(len(seen), 2, "the output changed with the hash seed")
        expected = [self.tree] + [os.path.join(self.tree, n) for n in ("alpha", "beta")]
        grown = json.loads(self.cli("--json", "growth", "--min-size", "1", "-n", "3").stdout)
        self.assertEqual([c["path"] for c in grown["changes"]], expected)
        top = json.loads(self.cli("--json", "top", "-n", "3").stdout)
        self.assertEqual([c["path"] for c in top], expected)


class TestGrowthShrinkOnly(Base):
    """A tree that only shrank is not "unchanged" (the header shows the drop)."""

    def setUp(self):
        super().setUp()
        write(os.path.join(self.tree, "big/f.bin"), 5 * 1048576)
        write(os.path.join(self.tree, "keep/f.bin"), 1048576)
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        os.unlink(os.path.join(self.tree, "big/f.bin"))
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")

    def test_it_says_directories_shrank_and_how_to_see_them(self):
        proc = self.cli("growth", "--min-size", "1")
        self.assertIn("net -5.0M", proc.stdout)
        self.assertNotIn("nothing changed", proc.stdout)
        self.assertIn("shrank", proc.stdout)
        self.assertIn("--shrink", proc.stdout)
        shown = self.cli("growth", "--min-size", "1", "--shrink").stdout
        self.assertIn(os.path.join(self.tree, "big"), shown)

    def test_a_tree_that_did_not_change_still_says_so(self):
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        proc = self.cli("growth", "--min-size", "1")
        self.assertIn("nothing changed", proc.stdout)
        self.assertNotIn("shrank", proc.stdout)

    def test_json_is_unchanged_by_the_note(self):
        out = json.loads(self.cli("--json", "growth", "--min-size", "1").stdout)
        self.assertEqual(out["changes"], [])
        self.assertEqual(out["net"], -5 * 1048576)


class TestDatabaseModes(Base):
    """The database lists the large directories of the disk: owner only (0600, 0700)."""

    def with_umask(self, mask):
        previous = os.umask(mask)
        self.addCleanup(os.umask, previous)

    def test_a_new_database_and_its_new_directory_are_private(self):
        self.with_umask(0o022)
        write(os.path.join(self.tree, "a.bin"), 1048576)
        db = os.path.join(self.root, "newdir", "sub", "x.sqlite")
        self.assertEqual(run_main("--db", db, "snap", self.tree, "-q").returncode, 0)
        self.assertEqual(stat.S_IMODE(os.stat(db).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(db)).st_mode), 0o700)

    def test_the_default_location_is_private_too(self):
        self.with_umask(0o022)
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.with_env("snap", self.tree, "-q", env={})
        folder = os.path.join(os.environ["XDG_DATA_HOME"], "grew")
        self.assertEqual(stat.S_IMODE(os.stat(folder).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(folder, "snapshots.db")).st_mode),
                         0o600)

    def test_the_umask_can_only_tighten_it_and_existing_things_are_left_alone(self):
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.with_umask(0o077)
        fresh = os.path.join(self.root, "u.sqlite")
        run_main("--db", fresh, "snap", self.tree, "-q")
        self.assertEqual(stat.S_IMODE(os.stat(fresh).st_mode), 0o600)
        os.umask(0o022)
        shared = os.path.join(self.root, "shared.sqlite")
        run_main("--db", shared, "snap", self.tree, "-q")
        os.chmod(shared, 0o664)                      # somebody chose this on purpose
        run_main("--db", shared, "snap", self.tree, "-q")
        self.assertEqual(stat.S_IMODE(os.stat(shared).st_mode), 0o664)
        folder = os.path.join(self.root, "existing")
        os.makedirs(folder)
        os.chmod(folder, 0o755)
        run_main("--db", os.path.join(folder, "d.sqlite"), "snap", self.tree, "-q")
        self.assertEqual(stat.S_IMODE(os.stat(folder).st_mode), 0o755)


class TestLongDatabaseName(Base):
    def test_a_name_that_is_too_long_is_called_that_not_a_permission_problem(self):
        name = os.path.join(self.root, "a" * 300)
        for args in (["list"], ["snap", self.tree, "-q"]):
            with self.subTest(args=args):
                proc = run_main("--db", name, *args)
                self.assertEqual(proc.returncode, 1)
                self.no_traceback(proc)
                self.assertIn("too long", proc.stderr)
                self.assertNotIn("permissions", proc.stderr)


class TestRootThroughSymlinkAndDotDot(Base):
    """`lnk/..` is what the kernel and du say it is, not the textual parent."""

    def test_dot_dot_after_a_symlink_scans_the_real_parent(self):
        real = os.path.join(self.root, "real")
        write(os.path.join(real, "deep", "f.bin"), 3 * 1048576)
        cwd = os.path.join(self.root, "cwd")
        os.makedirs(cwd)
        os.symlink(os.path.join("..", "real", "deep"), os.path.join(cwd, "lnk"))
        previous = os.getcwd()
        os.chdir(cwd)
        self.addCleanup(os.chdir, previous)
        out = json.loads(self.cli("--json", "snap", "lnk/..", "-q", "--min-size", "1").stdout)
        self.assertEqual(out["root"], os.path.realpath(real))
        self.assertEqual(out["total"], du_bytes("lnk/.."))
        self.assertGreaterEqual(out["total"], 3 * 1048576)
        self.assertIn(os.path.realpath(real), self.cli("list", "lnk/..").stdout)

    def test_dot_dot_without_symlinks_and_a_symlinked_root_keep_their_names(self):
        write(os.path.join(self.tree, "a", "f.bin"), 1048576)
        os.makedirs(os.path.join(self.tree, "b"))
        out = json.loads(self.cli("--json", "snap", os.path.join(self.tree, "b", ".."),
                                  "-q", "--min-size", "1").stdout)
        self.assertEqual(out["root"], os.path.realpath(self.tree))
        link = os.path.join(self.root, "alias")
        os.symlink(self.tree, link)
        out = json.loads(self.cli("--json", "snap", link, "-q", "--min-size", "1").stdout)
        self.assertEqual(out["root"], link)             # not resolved: it is the name given


class TestExcludeWarnings(Base):
    """An --exclude that excludes nothing is said so, even under -q (cron)."""

    def setUp(self):
        super().setUp()
        write(os.path.join(self.tree, "keep", "f.bin"), 1048576)
        write(os.path.join(self.tree, "cache", "f.bin"), 2 * 1048576)

    def total(self, *extra):
        proc = self.cli("--json", "snap", self.tree, "-q", "--apparent", "--min-size", "1",
                        *extra)
        return json.loads(proc.stdout)["total"], proc.stderr

    def test_a_working_exclude_is_silent_and_excludes(self):
        total, err = self.total("--exclude", os.path.join(self.tree, "cache"))
        self.assertEqual(err, "")
        self.assertEqual(total, apparent_bytes(self.tree) - apparent_bytes(
            os.path.join(self.tree, "cache")))

    def test_a_bare_name_outside_the_root_is_reported(self):
        previous = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        total, err = self.total("--exclude", "cache")
        self.assertIn("--exclude cache is not inside", err)
        self.assertIn("excludes nothing", err)
        self.assertIn("current directory", err)
        self.assertEqual(total, apparent_bytes(self.tree))      # the snapshot is still taken
        total, err = self.total("--exclude", "tree/cache")      # relative to the cwd: works
        self.assertEqual(err, "")
        self.assertLess(total, apparent_bytes(self.tree))

    def test_a_path_inside_the_root_that_does_not_exist_is_reported(self):
        _, err = self.total("--exclude", os.path.join(self.tree, "caches"))
        self.assertIn("does not exist", err)
        self.assertIn("excludes nothing", err)

    def test_the_note_is_not_json_and_not_a_traceback(self):
        proc = self.cli("--json", "snap", self.tree, "-q", "--exclude", "/nowhere/at/all")
        self.no_traceback(proc)
        json.loads(proc.stdout)
        self.assertIn("--exclude /nowhere/at/all", proc.stderr)


class TestReaderFallbacks(Base):
    """_open_readonly tries the next way in only for the failures that one can cure."""

    def setUp(self):
        super().setUp()
        write(os.path.join(self.tree, "a.bin"), 1048576)
        self.cli("snap", self.tree, "-q")

    def unwritable(self):
        real = os.access
        return mock.patch.object(
            g.os, "access", lambda p, mode, **k: False if mode == os.W_OK else real(p, mode, **k))

    def failing_for(self, marker, message):
        real = g._open
        tried = []

        def fake(target, **kwargs):
            tried.append(target)
            if marker in target:
                raise sqlite3.OperationalError(message)
            return real(target, **kwargs)
        return mock.patch.object(g, "_open", fake), tried

    def test_mode_ro_is_the_next_way_in_when_immutable_is_refused(self):
        patch, tried = self.failing_for("immutable=1", "attempt to write a readonly database")
        with self.unwritable(), patch:
            db, objects = g._open_readonly(self.db)
        db.close()
        self.assertIn("snapshots", objects)
        self.assertEqual([("immutable=1" in t, "mode=ro" in t) for t in tried],
                         [(True, False), (False, True)])

    def test_an_ordinary_connection_that_hits_a_size_limit_falls_back_to_a_read_only_one(self):
        tried = []
        real = g._open   # the ordinary target is the bare path; the others are file: URIs

        def fake(target, **kwargs):
            tried.append(target)
            if target == self.db:
                raise sqlite3.OperationalError("disk I/O error")
            return real(target, **kwargs)
        with mock.patch.object(g, "_open", fake):
            db, _ = g._open_readonly(self.db)
        db.close()
        self.assertEqual(tried[0], self.db)
        self.assertGreater(len(tried), 1)

    def test_other_failures_are_raised_at_once_not_retried(self):
        for message in ("database disk image is malformed", "database is locked",
                        "file is not a database"):
            with self.subTest(message=message):
                patch, tried = self.failing_for("", message)
                with patch:
                    with self.assertRaises(sqlite3.OperationalError):
                        g._open_readonly(self.db)
                self.assertEqual(len(tried), 1, "an error that no other mode cures was retried")


class TestDocumentation(unittest.TestCase):
    """The man page and README must keep describing what the tool really does."""

    @staticmethod
    def read(name):
        with open(os.path.join(HERE, name), encoding="utf-8") as f:
            return f.read()

    @staticmethod
    def plain(roff):
        """The man page as a reader sees it: font changes and escaped hyphens removed."""
        text = re.sub(r"\\f[BIRP]|\\&", "", roff).replace("\\-", "-")
        return re.sub(r"\s+", " ", text)         # a phrase may wrap across lines

    def test_man_page_prose_about_behaviour_is_still_true(self):
        man = self.plain(self.read("grew.1"))
        self.assertIn("Supported by every command, including prune", man)
        self.assertIn("list and prune finding nothing for a path", man)
        self.assertIn("Print nothing on success", man)
        # The sentence is true: prune accepts --json before and after the command
        # (parsing only; TestPruneOutputDetails runs it against a scratch database).
        parser = g.build_parser()
        for argv in (["--json", "prune"], ["prune", "--json"]):
            self.assertTrue(parser.parse_args(argv).json)

    def test_every_skipped_pseudo_filesystem_is_documented(self):
        for name in ("README.md", "grew.1"):
            text = self.plain(self.read(name))
            for path in sorted(g.SKIP_DIRS):
                with self.subTest(file=name, path=path):
                    self.assertIn(path, text, f"{name} does not mention that {path} is skipped")

    def test_new_behaviour_is_in_the_docs_that_describe_it(self):
        man = self.plain(self.read("grew.1"))
        for needle in ("0600", "relative", "mounted read-only", "--shrink"):
            with self.subTest(needle=needle):
                self.assertIn(needle, man)

class TestHelpAndPackaging(Base):
    """What a user sees from --help, and what the pip-installed command runs."""

    def test_every_option_and_argument_explains_itself(self):
        parser = g.build_parser()
        subparsers = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        for name, sub in [("grew", parser)] + sorted(subparsers.choices.items()):
            for action in sub._actions:
                if isinstance(action, (argparse._HelpAction, argparse._SubParsersAction)):
                    continue
                with self.subTest(command=name, option=action.option_strings or action.dest):
                    self.assertTrue(action.help, "no help text")

    def test_db_help_names_the_real_default_file(self):
        self.assertIn("$XDG_DATA_HOME/grew/snapshots.db", run_main("--help").stdout)

    def test_list_shows_no_change_across_a_switch_of_measurement(self):
        """An --apparent total minus an allocated one means nothing; growth refuses it too."""
        for i in range(30):
            write(os.path.join(self.tree, f"f{i}.txt"), 3)
        self.cli("snap", self.tree, "-q", "--min-size", "1")
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        self.cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        totals = [s["total"] for s in json.loads(self.cli("--json", "list").stdout)]
        self.assertNotEqual(totals[0], totals[1], "the two measurements should differ here")
        rows = [line for line in self.cli("--no-color", "list").stdout.splitlines() if self.tree in line]
        self.assertEqual(len(rows), 3)
        # The change column follows the root path; the random temp path itself may hold "-2".
        after = [row.split(self.tree, 1)[1].strip() for row in rows]
        self.assertEqual(after[1], "", "a change was shown across the switch")
        self.assertEqual(after[2], "", "identical apparent snapshots show no change")

    def test_the_installed_command_runs_the_same_entry_point_as_the_file(self):
        with open(os.path.join(HERE, "pyproject.toml"), encoding="utf-8") as f:
            scripts = re.search(r"^\[project\.scripts\]\n(?:#[^\n]*\n)*grew = \"grew:(\w+)\"", f.read(), re.M)
        self.assertIsNotNone(scripts, "pyproject.toml does not define the grew command")
        with open(GREW, encoding="utf-8") as f:
            main_block = re.search(r'^if __name__ == "__main__":\n\s+sys\.exit\((\w+)\(\)\)', f.read(), re.M)
        self.assertIsNotNone(main_block)
        self.assertEqual(scripts.group(1), main_block.group(1))


class TestPython38Syntax(unittest.TestCase):
    """`make lint`: the grammar check plus what ast.parse cannot see on a newer Python.

    ast.parse(feature_version=(3, 8)) rejects match, except* and PEP 695, but a
    3.12+ interpreter still accepts f-strings that reuse their own quote (or
    hold a backslash) inside the braces, and a parenthesised multi-item `with`.
    Both break on 3.8, so they are found from the tokens.
    """

    FILES = ("grew.py", "test_grew.py", "test_hardening.py")

    @staticmethod
    def violations(source, name="<source>"):
        import ast
        import tokenize
        try:
            ast.parse(source, name, feature_version=(3, 8))
        except SyntaxError as exc:
            if "Parenthesized context managers" not in exc.msg:
                return [f"{name}:{exc.lineno}: {exc.msg}"]
            # Python 3.9-3.11 refuse every parenthesised `with`, including the
            # plain `with (open(a)):`, which is just a parenthesised expression
            # and fine on 3.8. Which ones really are 3.9+ is decided below from
            # the tokens; here the rest of the file still gets its grammar check.
            try:
                ast.parse(source, name, feature_version=(3, 9))
            except SyntaxError as again:
                return [f"{name}:{again.lineno}: {again.msg}"]
        found = []
        skip = (tokenize.NL, tokenize.COMMENT, tokenize.NEWLINE)
        tokens = [t for t in tokenize.generate_tokens(io.StringIO(source).readline)
                  if t.type not in skip]

        start = getattr(tokenize, "FSTRING_START", None)
        end = getattr(tokenize, "FSTRING_END", None)
        if start is not None:                      # the 3.12+ tokenizer
            triple = ('"' * 3, "'" * 3)

            def delimiter(text):
                body = text.lstrip("rRbBuUfF")
                return body[:3] if body[:3] in triple else body[:1]

            open_strings = []
            for tok in tokens:
                if tok.type == end:
                    open_strings.pop()
                    continue
                if tok.type not in (start, tokenize.STRING):
                    continue
                quote = delimiter(tok.string)
                # Inside an f-string, only the braces' contents are tokens, so any
                # string seen while one is open sits in an expression.
                for outer in open_strings:
                    if outer == quote or (len(outer) == 1 and quote[:1] == outer):
                        found.append(f"{name}:{tok.start[0]}: f-string reuses its own "
                                     f"quote {outer} inside the braces")
                        break
                if open_strings and "\\" in tok.string:
                    found.append(f"{name}:{tok.start[0]}: backslash in an f-string expression")
                if tok.type == start:
                    open_strings.append(quote)

        for i, tok in enumerate(tokens):
            if tok.type == tokenize.NAME and tok.string == "with" and i + 1 < len(tokens) \
                    and tokens[i + 1].string == "(":
                depth, j, has_as, has_comma = 0, i + 1, False, False
                while j < len(tokens):
                    if tokens[j].type == tokenize.OP and tokens[j].string in "([{":
                        depth += 1
                    elif tokens[j].type == tokenize.OP and tokens[j].string in ")]}":
                        depth -= 1
                        if depth == 0:
                            break
                    elif depth == 1 and tokens[j].type == tokenize.NAME \
                            and tokens[j].string == "as":
                        has_as = True
                    elif depth == 1 and tokens[j].type == tokenize.OP \
                            and tokens[j].string == ",":
                        has_comma = True      # with (a, b): a tuple on 3.8, items on 3.9+
                    j += 1
                if (has_as or has_comma) and j + 1 < len(tokens) \
                        and tokens[j + 1].string == ":":
                    found.append(f"{name}:{tok.start[0]}: parenthesised with-items "
                                 "need Python 3.10")
        return found

    def test_the_project_files_parse_with_the_python_38_grammar(self):
        for name in self.FILES:
            with self.subTest(file=name):
                with open(os.path.join(HERE, name), encoding="utf-8") as f:
                    self.assertEqual(self.violations(f.read(), name), [])

    def test_the_check_catches_what_python_38_would_reject(self):
        bad = {
            "match": "match x:\n    case 1:\n        pass\n",
            "same-quote f-string": 'd = {"x": 1}\ny = f"{d["x"]}"\n',
            "same-quote single": "d = {'x': 1}\ny = f'{d['x']}'\n",
            "nested f-string": 'x = f"{f"{1}"}"\n',
            "backslash in braces": 'y = f"{chr(10).join(a) + \'\\n\'}"\n',
            "parenthesised with": "with (open(a) as x, open(b) as y):\n    pass\n",
            "parenthesised with, no as": "with (open(a), open(b)):\n    pass\n",
            "except star": "try:\n    pass\nexcept* ValueError:\n    pass\n",
        }
        for label, source in bad.items():
            with self.subTest(case=label):
                self.assertTrue(self.violations(source), f"{label} was not caught")

    def test_the_check_accepts_what_python_38_accepts(self):
        good = [
            "d = {'x': 1}\ny = f\"{d['x']}\"\n",
            "d = {'x': 1}\ny = f'''{d['x']}'''\n",
            'y = f"{1:>{5}}"\n',
            'z = f"{\'a\'}" f\'{"b"}\'\n',
            "with (open(a)):\n    pass\n",
            "with open(a) as x, open(b) as y:\n    pass\n",
            "with a, b:\n    pass\n",
        ]
        for source in good:
            with self.subTest(source=source):
                self.assertEqual(self.violations(source), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
