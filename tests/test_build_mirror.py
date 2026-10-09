#!/usr/bin/env python3
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import build_mirror as mb  # noqa: E402


PUBLISHED = """\
81263a4906c7d0a3c51daef556b3d772b4082253\tHEAD
81263a4906c7d0a3c51daef556b3d772b4082253\trefs/heads/1.1.1zi-carry
fb26261ef6aa8f1b3867f1a32e9a2a0d80057051\trefs/heads/OpenSSL_1_1_1-continued
b87631dacfb74cc044ba0955e3f0812b191e6450\trefs/tags/carry/1.1.1zi-jz1
071b845c8896455fd5f4071840b2bb2a44c287d4\trefs/tags/tarball/1.1.1za
fb26261ef6aa8f1b3867f1a32e9a2a0d80057051\trefs/tags/tarball/1.1.1zi
"""


def result(**over):
    r = {"repo": None,
         "heads": {"OpenSSL_1_1_1-continued": "fb26261ef6aa8f1b3867f1a32e9a2a0d80057051"},
         "tags": {"tarball/1.1.1za": "071b845c8896455fd5f4071840b2bb2a44c287d4",
                  "tarball/1.1.1zi": "fb26261ef6aa8f1b3867f1a32e9a2a0d80057051"},
         "trees": {}}
    r.update(over)
    return r


def git(repo, *args, **kw):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@example.invalid", GIT_AUTHOR_DATE="1700000000 +0000",
               GIT_COMMITTER_DATE="1700000000 +0000")
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                          env=env, **kw).stdout.strip()


class LsRemoteTests(unittest.TestCase):
    def test_parses_refs(self):
        refs = mb.parse_ls_remote(PUBLISHED)
        self.assertEqual(refs["refs/tags/tarball/1.1.1zi"], "fb26261ef6aa8f1b3867f1a32e9a2a0d80057051")
        self.assertEqual(len(refs), 6)

    def test_peeled_annotated_tag_wins(self):
        text = PUBLISHED + ("1" * 40 + "\trefs/tags/carry/1.1.1zi-jz2\n" + "2" * 40 + "\trefs/tags/carry/1.1.1zi-jz2^{}\n")
        self.assertEqual(mb.parse_ls_remote(text)["refs/tags/carry/1.1.1zi-jz2"], "2" * 40)

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            mb.parse_ls_remote("not-a-sha\trefs/heads/x\n")


class CompareTests(unittest.TestCase):
    def published(self):
        refs = mb.parse_ls_remote(PUBLISHED)
        del refs["refs/tags/carry/1.1.1zi-jz1"]
        return refs

    def test_equal_ids_pass(self):
        ok, report = mb.compare(result(), self.published())
        self.assertTrue(ok, report)
        self.assertEqual({c["status"] for c in report["checks"]}, {"equal"})

    def test_mutated_tarball_tag_fails(self):
        pub = self.published()
        pub["refs/tags/tarball/1.1.1za"] = "0" * 40
        ok, report = mb.compare(result(), pub)
        self.assertFalse(ok)
        self.assertEqual(report["problems"], ["refs/tags/tarball/1.1.1za"])

    def test_mutated_continued_head_fails(self):
        ok, report = mb.compare(result(heads={"OpenSSL_1_1_1-continued": "3" * 40}), self.published())
        self.assertFalse(ok)
        self.assertIn("refs/heads/OpenSSL_1_1_1-continued", report["problems"])

    def test_published_tag_not_rebuilt_fails(self):
        pub = self.published()
        pub["refs/tags/tarball/1.1.1zj"] = "4" * 40
        ok, report = mb.compare(result(), pub)
        self.assertFalse(ok)
        self.assertIn("refs/tags/tarball/1.1.1zj", report["problems"])

    def test_rebuilt_but_unpublished_tag_is_reported_not_failed(self):
        r = result()
        r["tags"]["tarball/1.1.1zj"] = "5" * 40
        ok, report = mb.compare(r, self.published())
        self.assertTrue(ok)
        self.assertIn(("refs/tags/tarball/1.1.1zj", "unpublished"),
                      [(c["ref"], c["status"]) for c in report["checks"]])

    def test_no_published_tarball_tags_fails(self):
        pub = {k: v for k, v in self.published().items() if not k.startswith("refs/tags/tarball/")}
        ok, _ = mb.compare(result(), pub)
        self.assertFalse(ok)


class CarryTreeTests(unittest.TestCase):
    """Carry tags are compared by tree: the same tree under another commit id passes, another tree fails."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        repo = Path(cls.tmp.name)
        git(repo, "init", "-q")
        (repo / "f").write_text("carry\n")
        git(repo, "add", "f")
        git(repo, "commit", "-q", "--no-gpg-sign", "-m", "carry")
        cls.repo = repo
        cls.commit = git(repo, "rev-parse", "HEAD")
        cls.tree = git(repo, "rev-parse", "HEAD^{tree}")
        cls.recommit = git(repo, "commit-tree", "--no-gpg-sign", cls.tree, "-m", "same tree, other id")
        (repo / "f").write_text("other\n")
        git(repo, "commit", "-q", "--no-gpg-sign", "-am", "other tree")
        cls.other = git(repo, "rev-parse", "HEAD")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_compare(self, published_carry):
        r = result(repo=str(self.repo))
        r["tags"]["carry/1.1.1zi-jz1"] = self.commit
        r["trees"]["carry/1.1.1zi-jz1"] = self.tree
        pub = mb.parse_ls_remote(PUBLISHED)
        pub["refs/tags/carry/1.1.1zi-jz1"] = published_carry
        return mb.compare(r, pub)

    def test_same_tree_other_id_passes(self):
        ok, report = self.run_compare(self.recommit)
        self.assertTrue(ok, report)
        carry = next(c for c in report["checks"] if c["ref"] == "refs/tags/carry/1.1.1zi-jz1")
        self.assertEqual(carry["status"], "tree-equal")
        self.assertFalse(carry["same_id"])

    def test_other_tree_fails(self):
        ok, report = self.run_compare(self.other)
        self.assertFalse(ok)
        self.assertEqual(report["problems"], ["refs/tags/carry/1.1.1zi-jz1"])

    def test_missing_published_object_fails(self):
        ok, report = self.run_compare("6" * 40)
        self.assertFalse(ok)

    def test_published_carry_not_rebuilt_is_informational(self):
        pub = mb.parse_ls_remote(PUBLISHED)
        pub["refs/tags/carry/1.1.1zi-jz2"] = "7" * 40
        del pub["refs/tags/carry/1.1.1zi-jz1"]
        ok, report = mb.compare(result(), pub)
        self.assertTrue(ok)
        self.assertIn(("refs/tags/carry/1.1.1zi-jz2", "not-rebuilt"),
                      [(c["ref"], c["status"]) for c in report["checks"]])


class InputTests(unittest.TestCase):
    def make_tarball(self, path, changes):
        with tarfile.open(path, "w:gz") as tf:
            data = changes.encode()
            ti = tarfile.TarInfo("openssl-1.1.1w/CHANGES")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))

    def test_tarball_pin_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            self.make_tarball(Path(d, "openssl-1.1.1w.tar.gz"), "x")
            with self.assertRaises(mb.BuildError):
                mb.Inputs(d).tarball("w")

    def test_missing_srpm_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(mb.BuildError):
                mb.Inputs(d).srpm("zi")

    def test_carry_patches_optional(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(mb.Inputs(d).carry_patches())
            Path(d, "carry").mkdir()
            for n in ("0001-a.patch", "0002-b.patch"):
                Path(d, "carry", n).write_text("")
            self.assertEqual([p.name for p in mb.Inputs(d).carry_patches()], ["0001-a.patch", "0002-b.patch"])

    def test_changes_sections_from_tarball(self):
        text = (" Changes between 1.1.1zh and 1.1.1zi [25 Aug 2026]\n\n  *) a (CVE-2026-1)\n\n"
                " Changes between 1.1.1zg and 1.1.1zh [1 Jun 2026]\n\n  *) b\n")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "t.tar.gz")
            self.make_tarball(p, text)
            secs = mb.changes_sections(p)
        self.assertEqual([(s[0], s[1], s[2]) for s in secs],
                         [("1.1.1zh", "1.1.1zi", "25 Aug 2026"), ("1.1.1zg", "1.1.1zh", "1 Jun 2026")])
        self.assertIn("CVE-2026-1", secs[0][3])

    def test_recorded_mirror_path_is_kept_for_the_published_ids(self):
        # The published import messages name this path; changing it would change every commit id.
        self.assertIn("4f8fa06cd2aae03f75376d4f686e3f2d75ccd73ade02131072abdefd9ce64bbf", mb.AL2_MIRROR_RECORDED)
        source = Path(mb.__file__).read_text()
        self.assertNotIn(".local/openssl-strategy", source)
        self.assertNotIn(".local/openssl-shared", source)


if __name__ == "__main__":
    unittest.main()
