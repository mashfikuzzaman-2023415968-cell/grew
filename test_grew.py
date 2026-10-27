#!/usr/bin/env python3
"""Tests for grew. Run with: python3 -m unittest -v test_grew  (or ./test_grew.py)"""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
GREW = os.path.join(HERE, "grew.py")

# The tool has no .py extension, so load it as a module explicitly.
_spec = importlib.util.spec_from_loader("grewmod",
         importlib.machinery.SourceFileLoader("grewmod", GREW))
g = importlib.util.module_from_spec(_spec)
sys.modules["grewmod"] = g   # dataclasses resolve types via sys.modules
_spec.loader.exec_module(g)


def du_bytes(path):
    """Ground truth from du, in bytes, for cross-checking the scanner.

    --block-size=1 is GNU only; BSD du (macOS) rejects it. BLOCKSIZE=512 is
    honoured by both, so ask for 512-byte blocks and multiply. The other
    block-size variables take precedence on GNU du, so they are removed.
    """
    env = {k: v for k, v in os.environ.items()
           if k not in ("BLOCKSIZE", "BLOCK_SIZE", "DU_BLOCK_SIZE", "POSIXLY_CORRECT")}
    env["BLOCKSIZE"] = "512"
    out = subprocess.run(["du", "-s", path], capture_output=True, text=True, env=env)
    return int(out.stdout.split()[0]) * 512


def run_main(*argv):
    """Run grew's main() in this process, as a user would see it.

    Same parser and code with no interpreter start-up, which is most of what a
    subprocess costs. The tests that are about the process itself (exit status,
    a real stdout) pass process=True.
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


def apparent_bytes(path):
    """What du --apparent-size reports: file and symlink sizes, never directories.

    A directory's st_size is a filesystem artefact (4096 on ext4, 40 + 20 per
    entry on tmpfs), so --apparent leaves it out and a hand-computed total is
    the same everywhere. Hardlinks count once; symlinks are not followed.
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


def write(path, size_bytes=0, content=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content if content is not None else b"\0" * size_bytes)


class TempTree(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="grewtest-")
        self.db = os.path.join(self.root, "db.sqlite")
        self.tree = os.path.join(self.root, "tree")
        os.makedirs(self.tree)
        # Never let a regression write into the developer's real database.
        sandbox = mock.patch.dict(os.environ, {
            "HOME": os.path.join(self.root, "home-sandbox"),
            "XDG_DATA_HOME": os.path.join(self.root, "xdg-sandbox")})
        sandbox.start()
        self.addCleanup(sandbox.stop)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def apparent(self):
        """Oracle for --apparent: bytes of files and symlinks, directories excluded."""
        return apparent_bytes(self.tree)

    def assertFileBytes(self, actual, file_bytes, msg=None):
        """Directory inodes add a few KB; assert that overhead stays small."""
        slack = 64 * 1024
        self.assertGreaterEqual(actual, file_bytes, msg)
        self.assertLess(actual, file_bytes + slack, msg)

    def run_cli(self, *args, expect_ok=True, process=False):
        if process:
            proc = subprocess.run([sys.executable, GREW, "--db", self.db, *args],
                                  capture_output=True, text=True)
        else:
            proc = run_main("--db", self.db, *args)
        if expect_ok:
            self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        return proc


# --------------------------------------------------------------------------- #

class TestFormatting(unittest.TestCase):
    def test_human_readable_sizes(self):
        self.assertEqual(g.human(0), "0B")
        self.assertEqual(g.human(512), "512B")
        self.assertEqual(g.human(1024), "1.0K")
        self.assertEqual(g.human(1536), "1.5K")
        self.assertEqual(g.human(1048576), "1.0M")
        self.assertEqual(g.human(1073741824), "1.0G")

    def test_large_values_lose_decimal(self):
        # 100M+ reads better without a decimal place
        self.assertEqual(g.human(200 * 1048576), "200M")

    def test_signed_output(self):
        self.assertTrue(g.human(1024, signed=True).startswith("+"))
        self.assertTrue(g.human(-1024, signed=True).startswith("-"))
        self.assertEqual(g.human(-1024, signed=True), "-1.0K")

    def test_parse_size(self):
        self.assertEqual(g.parse_size("10M"), 10 * 1048576)
        self.assertEqual(g.parse_size("1G"), 1073741824)
        self.assertEqual(g.parse_size("500K"), 512000)
        self.assertEqual(g.parse_size("2048"), 2048)
        self.assertEqual(g.parse_size("1.5M"), int(1.5 * 1048576))

    def test_parse_size_rejects_nonsense(self):
        for bad in ("banana", "10X", "", "M"):
            with self.assertRaises(Exception):
                g.parse_size(bad)

    def test_parse_duration(self):
        self.assertEqual(g.parse_duration("7d"), 604800)
        self.assertEqual(g.parse_duration("12h"), 43200)
        self.assertEqual(g.parse_duration("2w"), 1209600)

    def test_parse_duration_rejects_nonsense(self):
        for bad in ("7y", "soon", "d"):
            with self.assertRaises(Exception):
                g.parse_duration(bad)


class TestScanning(TempTree):
    def test_counts_nested_sizes_cumulatively(self):
        write(os.path.join(self.tree, "a/file.bin"), 2 * 1048576)
        write(os.path.join(self.tree, "a/b/file.bin"), 3 * 1048576)
        res = g.scan(self.tree, apparent=True, min_size=0)
        # Directory inodes count too, so sizes are "file bytes plus a little".
        self.assertFileBytes(res.sizes[self.tree], 5 * 1048576)
        self.assertFileBytes(res.sizes[os.path.join(self.tree, "a")], 5 * 1048576)
        self.assertFileBytes(res.sizes[os.path.join(self.tree, "a/b")], 3 * 1048576)
        self.assertEqual(res.files, 2)

    def test_min_size_prunes_small_dirs_but_keeps_root(self):
        write(os.path.join(self.tree, "big/file.bin"), 5 * 1048576)
        write(os.path.join(self.tree, "tiny/file.bin"), 10)
        res = g.scan(self.tree, apparent=True, min_size=1048576)
        self.assertIn(os.path.join(self.tree, "big"), res.sizes)
        self.assertNotIn(os.path.join(self.tree, "tiny"), res.sizes)
        self.assertIn(self.tree, res.sizes, "root must always be recorded")

    def test_symlinks_are_not_followed(self):
        write(os.path.join(self.tree, "real/file.bin"), 4 * 1048576)
        os.symlink(os.path.join(self.tree, "real"), os.path.join(self.tree, "link"))
        res = g.scan(self.tree, apparent=True, min_size=0)
        # Following the link would double the total.
        self.assertFileBytes(res.sizes[self.tree], 4 * 1048576)

    def test_symlink_loop_does_not_hang(self):
        d = os.path.join(self.tree, "loop")
        os.makedirs(d)
        os.symlink(d, os.path.join(d, "self"))
        res = g.scan(self.tree, apparent=True, min_size=0)  # must terminate
        self.assertFileBytes(res.sizes[self.tree], 0)

    def test_hardlinks_counted_once(self):
        target = os.path.join(self.tree, "a/file.bin")
        write(target, 4 * 1048576)
        os.makedirs(os.path.join(self.tree, "b"), exist_ok=True)
        os.link(target, os.path.join(self.tree, "b/same.bin"))
        res = g.scan(self.tree, apparent=True, min_size=0)
        self.assertFileBytes(res.sizes[self.tree], 4 * 1048576,
                             "a hardlink should not be billed twice")

    def test_exclude_paths(self):
        write(os.path.join(self.tree, "keep/file.bin"), 2 * 1048576)
        write(os.path.join(self.tree, "skip/file.bin"), 8 * 1048576)
        res = g.scan(self.tree, apparent=True, min_size=0,
                     exclude=[os.path.join(self.tree, "skip")])
        self.assertFileBytes(res.sizes[self.tree], 2 * 1048576)
        self.assertNotIn(os.path.join(self.tree, "skip"), res.sizes)

    def test_unreadable_directory_is_counted_not_fatal(self):
        if os.geteuid() == 0:
            self.skipTest("root can read anything")
        secret = os.path.join(self.tree, "secret")
        os.makedirs(secret)
        write(os.path.join(secret, "f.bin"), 1024)
        os.chmod(secret, 0o000)
        try:
            res = g.scan(self.tree, apparent=True, min_size=0)
            self.assertGreaterEqual(res.errors, 1)
        finally:
            os.chmod(secret, 0o755)

    def test_empty_tree(self):
        res = g.scan(self.tree, apparent=True, min_size=0)
        self.assertFileBytes(res.total, 0)
        self.assertEqual(res.files, 0)

    def test_apparent_vs_allocated(self):
        # A small file occupies a whole block, so allocated >= apparent.
        write(os.path.join(self.tree, "small.bin"), 10)
        app = g.scan(self.tree, apparent=True, min_size=0).total
        alloc = g.scan(self.tree, apparent=False, min_size=0).total
        self.assertGreaterEqual(alloc, app)

    def test_matches_du_exactly(self):
        """The strongest correctness check: agree with the system tool."""
        write(os.path.join(self.tree, "a/one.bin"), 3 * 1048576)
        write(os.path.join(self.tree, "a/b/two.bin"), 5 * 1048576)
        write(os.path.join(self.tree, "c/three.bin"), 1 * 1048576)
        res = g.scan(self.tree, apparent=False, min_size=0)
        expected = du_bytes(self.tree)
        self.assertEqual(res.total, expected,
                         f"grew {res.total} vs du {expected}")

    def test_matches_du_with_hardlinks(self):
        target = os.path.join(self.tree, "a/file.bin")
        write(target, 4 * 1048576)
        os.makedirs(os.path.join(self.tree, "b"), exist_ok=True)
        os.link(target, os.path.join(self.tree, "b/same.bin"))
        res = g.scan(self.tree, apparent=False, min_size=0)
        self.assertEqual(res.total, du_bytes(self.tree),
                         "hardlink handling should match du")


class TestDiff(unittest.TestCase):
    def test_detects_growth_and_shrink(self):
        before = {"/a": 100, "/b": 500}
        after = {"/a": 300, "/b": 100}
        changes = {c.path: c.delta for c in g.diff(before, after)}
        self.assertEqual(changes["/a"], 200)
        self.assertEqual(changes["/b"], -400)

    def test_sorted_by_magnitude(self):
        changes = g.diff({"/a": 0, "/b": 0}, {"/a": 10, "/b": 900})
        self.assertEqual(changes[0].path, "/b")

    def test_new_and_gone_flags(self):
        changes = {c.path: c for c in g.diff({"/old": 50}, {"/new": 50})}
        self.assertTrue(changes["/new"].is_new)
        self.assertTrue(changes["/old"].is_gone)

    def test_threshold_filters_noise(self):
        changes = g.diff({"/a": 0}, {"/a": 100}, threshold=500)
        self.assertEqual(changes, [])


class TestBlame(unittest.TestCase):
    """The parent-suppression logic is the heart of the tool."""

    def test_suppresses_parents_explained_by_one_child(self):
        changes = g.diff(
            {"/p": 0, "/p/app": 0, "/p/app/node_modules": 0},
            {"/p": 1000, "/p/app": 1000, "/p/app/node_modules": 1000},
        )
        kept = [c.path for c in g.blame(changes)]
        self.assertEqual(kept, ["/p/app/node_modules"],
                         "only the directory actually responsible should remain")

    def test_keeps_parent_when_growth_is_spread_across_children(self):
        changes = g.diff(
            {"/p": 0, "/p/a": 0, "/p/b": 0},
            {"/p": 1000, "/p/a": 500, "/p/b": 500},
        )
        kept = [c.path for c in g.blame(changes)]
        self.assertIn("/p", kept,
                      "a parent whose growth is split should still be reported")

    def test_does_not_suppress_across_opposite_directions(self):
        # Parent grew; child shrank. The parent is still the real story.
        changes = g.diff({"/p": 0, "/p/a": 1000}, {"/p": 1000, "/p/a": 0})
        kept = [c.path for c in g.blame(changes)]
        self.assertIn("/p", kept)

    def test_prefix_match_is_path_aware(self):
        # /pow must not be treated as a child of /p
        changes = g.diff({"/p": 0, "/pow": 0}, {"/p": 1000, "/pow": 1000})
        kept = sorted(c.path for c in g.blame(changes))
        self.assertEqual(kept, ["/p", "/pow"])


class TestCLI(TempTree):
    def test_snap_then_growth_reports_the_culprit(self):
        write(os.path.join(self.tree, "media/video.bin"), 4 * 1048576)
        self.run_cli("snap", self.tree, "--apparent", "--min-size", "1")
        write(os.path.join(self.tree, "node_modules/dep.bin"), 20 * 1048576)
        self.run_cli("snap", self.tree, "--apparent", "--min-size", "1")

        out = self.run_cli("growth", "--min-size", "1").stdout
        self.assertIn("node_modules", out)
        self.assertIn("+20.0M", out)

    def test_growth_without_two_snapshots_explains_itself(self):
        self.run_cli("snap", self.tree, "-q")
        proc = self.run_cli("growth", expect_ok=False, process=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("two snapshots", proc.stderr)

    def test_json_output_is_valid(self):
        write(os.path.join(self.tree, "a.bin"), 2 * 1048576)
        before = self.apparent()
        self.run_cli("snap", self.tree, "-q", "--apparent")
        write(os.path.join(self.tree, "b.bin"), 3 * 1048576)
        after = self.apparent()
        self.run_cli("snap", self.tree, "-q", "--apparent")
        out = self.run_cli("--json", "growth", "--min-size", "1", process=True).stdout
        data = json.loads(out)
        # The bytes of the file added, on every filesystem: a directory's own
        # st_size (which grows with its entries on tmpfs) is not counted.
        self.assertEqual(data["net"], after - before)
        self.assertEqual(data["net"], 3 * 1048576)
        self.assertIn("changes", data)

    def test_top_lists_biggest(self):
        write(os.path.join(self.tree, "big/f.bin"), 9 * 1048576)
        write(os.path.join(self.tree, "small/f.bin"), 1 * 1048576)
        self.run_cli("snap", self.tree, "-q", "--apparent", "--min-size", "1")
        out = self.run_cli("top").stdout
        self.assertLess(out.index("big"), out.index("small"),
                        "biggest directory should be listed first")

    def test_list_shows_snapshots(self):
        self.run_cli("snap", self.tree, "-q")
        out = self.run_cli("list").stdout
        self.assertIn(self.tree, out)

    def test_prune_keeps_the_newest(self):
        for _ in range(4):
            self.run_cli("snap", self.tree, "-q")
        self.run_cli("prune", "--keep", "2")
        out = self.run_cli("--json", "list").stdout
        self.assertEqual(len(json.loads(out)), 2)

    def test_no_color_produces_clean_output(self):
        write(os.path.join(self.tree, "a.bin"), 2 * 1048576)
        self.run_cli("snap", self.tree, "-q", "--apparent")
        write(os.path.join(self.tree, "b.bin"), 2 * 1048576)
        self.run_cli("snap", self.tree, "-q", "--apparent")
        out = self.run_cli("--no-color", "growth", "--min-size", "1").stdout
        self.assertNotIn("\033[", out)

    def test_snap_rejects_a_non_directory(self):
        proc = self.run_cli("snap", os.path.join(self.tree, "nope"), expect_ok=False,
                            process=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_help_and_version(self):
        self.assertIn("grew", self.run_cli("--version", process=True).stdout)
        self.assertIn("examples", self.run_cli("--help", process=True).stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
