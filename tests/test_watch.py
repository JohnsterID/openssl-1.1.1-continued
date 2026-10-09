#!/usr/bin/env python3
import copy
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import watch as w  # noqa: E402

MIRROR = "https://cdn.amazonlinux.com/2/core/2.0/SRPMS/abc/"


def primary(versions):
    pkgs = "".join(
        f'<package type="rpm"><name>openssl11</name><arch>src</arch>'
        f'<version epoch="1" ver="{v}" rel="{r}"/><checksum type="sha256" pkgid="YES">{"%064x" % i}</checksum>'
        f'<location href="../../../../../blobstore/{"%064x" % i}/openssl11-{v}-{r}.src.rpm"/></package>'
        for i, (v, r) in enumerate(versions))
    other = ('<package type="rpm"><name>openssl</name><arch>src</arch><version epoch="1" ver="1.0.2k" rel="1"/>'
             '<checksum type="sha256" pkgid="YES">ff</checksum><location href="x"/></package>')
    xml = ('<?xml version="1.0"?><metadata xmlns="http://linux.duke.edu/metadata/common" packages="2">'
           + other + pkgs + "</metadata>")
    return gzip.compress(xml.encode(), mtime=0)


def repomd(revision, prim, checksum=None):
    cs = checksum or hashlib.sha256(prim).hexdigest()
    return (f'<repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>{revision}</revision>'
            f'<data type="primary"><checksum type="sha256">{cs}</checksum>'
            f'<location href="repodata/primary.xml.gz"/></data></repomd>').encode()


def responses(**over):
    prim = over.pop("primary", primary([("1.1.1zh", "1.amzn2.0.1"), ("1.1.1zi", "1.amzn2.0.1")]))
    r = {
        w.AL2_MIRRORLIST: (MIRROR + "\n").encode(),
        MIRROR + "repodata/repomd.xml": repomd(over.pop("revision", 1790634640), prim, over.pop("checksum", None)),
        MIRROR + "repodata/primary.xml.gz": prim,
        w.SECADV_INDEX: over.pop("secadv_index", b'<a href="/news/secadv/20260825.txt">x</a> 20260929.txt'),
        w.SECADV_INDEX + "20260825.txt": b"old advisory",
        w.SECADV_INDEX + "20260929.txt": over.pop("secadv_body", b"OpenSSL Security Advisory 1.1.1 ..."),
        w.SECADV_INDEX + "20261020.txt": b"a new advisory affecting 1.1.1",
        w.VULNS_111: over.pop("vulns", b"CVE-2026-84782 fixed in 1.1.1zj (premium) CVE-2026-35189 1.1.1zi"),
        w.CPANEL_COMMITS: json.dumps(over.pop("cpanel", [{"sha": "c0bb148e692b5c334d3b08fa3fa12edeedbbd413",
                                     "commit": {"committer": {"date": "2026-10-01T20:55:10Z"},
                                                "message": "EA-13575: Patch ea-openssl11"}}])).encode(),
        w.KZ_REPO: json.dumps({"pushed_at": over.pop("kz_pushed", "2026-06-16T11:48:16Z"),
                               "default_branch": "master"}).encode(),
        w.KZ_TAGS: json.dumps([{"name": n} for n in over.pop("kz_tags", ["1.1.1zh", "1.1.1zg"])]).encode(),
        "ls-remote " + w.FORK: over.pop("fork", "81263a4906c7d0a3c51daef556b3d772b4082253\trefs/heads/1.1.1zi-carry\n"
                                        "fb26261ef6aa8f1b3867f1a32e9a2a0d80057051\trefs/tags/tarball/1.1.1zi\n").encode(),
    }
    for drop in over.pop("drop", []):
        del r[drop]
    assert not over, over
    return r


class WatchTests(unittest.TestCase):
    def run_watch(self, state, resp, only=None):
        with tempfile.TemporaryDirectory() as d:
            for key, data in resp.items():
                Path(d, w.fixture_name(key)).write_bytes(data)
            return w.watch(state, w.Fetcher(fixtures=d), only)

    def baseline(self):
        code, report, state = self.run_watch(None, responses())
        self.assertEqual(code, 1)
        self.assertEqual({c["what"] for c in report["changed"]}, {"no recorded state"})
        return state

    def assertChanged(self, resp, source, text=None):
        code, report, _ = self.run_watch(self.baseline(), resp)
        self.assertEqual(code, 1, report)
        self.assertEqual([c["source"] for c in report["changed"]], [source])
        if text:
            self.assertIn(text, report["changed"][0]["what"])
        return report

    def test_unchanged(self):
        code, report, state = self.run_watch(self.baseline(), responses())
        self.assertEqual(code, 0)
        self.assertEqual(report["verdict"], "unchanged")
        self.assertEqual(len(report["unchanged"]), 6)
        self.assertEqual(state["sources"]["al2"]["info"]["newest"], "1.1.1zi-1.amzn2.0.1")

    def test_al2_new_openssl11_1_1_1zj(self):
        prim = primary([("1.1.1zh", "1.amzn2.0.1"), ("1.1.1zi", "1.amzn2.0.1"), ("1.1.1zj", "1.amzn2.0.1")])
        report = self.assertChanged(responses(primary=prim, revision=1791000000), "al2", "1.1.1zj-1.amzn2.0.1")
        self.assertIn("event Z1", report["changed"][0]["what"])
        self.assertEqual(report["sources"]["al2"]["info"]["newest"], "1.1.1zj-1.amzn2.0.1")

    def test_al2_rebuild_of_zi_is_a_change_without_z1(self):
        prim = primary([("1.1.1zh", "1.amzn2.0.1"), ("1.1.1zi", "1.amzn2.0.1"), ("1.1.1zi", "1.amzn2.0.2")])
        report = self.assertChanged(responses(primary=prim), "al2", "1.1.1zi-1.amzn2.0.2")
        self.assertNotIn("Z1", report["changed"][0]["what"])

    def test_al2_revision_alone_is_not_a_change(self):
        code, report, _ = self.run_watch(self.baseline(), responses(revision=1799999999))
        self.assertEqual(code, 0, report)

    def test_al2_primary_checksum_mismatch_is_a_fetch_error(self):
        code, report, state = self.run_watch(self.baseline(), responses(checksum="0" * 64))
        self.assertEqual(code, 2)
        self.assertEqual(report["errors"][0]["source"], "al2")
        self.assertIn("al2", state["sources"])  # the reviewed state is kept for a failed source

    def test_secadv_new_advisory(self):
        idx = b"20260825.txt 20260929.txt 20261020.txt"
        self.assertChanged(responses(secadv_index=idx), "secadv", "newest")

    def test_secadv_same_name_new_content(self):
        self.assertChanged(responses(secadv_body=b"OpenSSL Security Advisory, updated"), "secadv", "sha256")

    def test_vulns_page_new_cve(self):
        page = b"CVE-2026-84782 1.1.1zj CVE-2026-35189 1.1.1zi CVE-2026-99999 1.1.1zk"
        self.assertChanged(responses(vulns=page), "vulns111", "cves")

    def test_cpanel_new_commit(self):
        c = [{"sha": "d" * 40, "commit": {"committer": {"date": "2026-10-20T00:00:00Z"}, "message": "EA-1: x"}}]
        self.assertChanged(responses(cpanel=c), "cpanel", "newest_commit")

    def test_kzalewski_new_tag(self):
        self.assertChanged(responses(kz_tags=["1.1.1zi", "1.1.1zh", "1.1.1zg"], kz_pushed="2026-10-20T00:00:00Z"),
                           "kzalewski", "tags")

    def test_fork_tag_moved(self):
        fork = ("81263a4906c7d0a3c51daef556b3d772b4082253\trefs/heads/1.1.1zi-carry\n"
                "0000000000000000000000000000000000000001\trefs/tags/tarball/1.1.1zi\n")
        self.assertChanged(responses(fork=fork), "fork", "refs/tags/tarball/1.1.1zi")

    def test_fork_new_tag_is_a_change_and_peeled(self):
        fork = ("81263a4906c7d0a3c51daef556b3d772b4082253\trefs/heads/1.1.1zi-carry\n"
                "fb26261ef6aa8f1b3867f1a32e9a2a0d80057051\trefs/tags/tarball/1.1.1zi\n"
                "d53cb3226086ce611f82a0c5a3d03c2c2b9a109a\trefs/tags/carry/1.1.1zi-jz2\n"
                "d952ab0f7d08d52ce12ee3177fe2b503e8263806\trefs/tags/carry/1.1.1zi-jz2^{}\n")
        report = self.assertChanged(responses(fork=fork), "fork", "refs/tags/carry/1.1.1zi-jz2")
        self.assertEqual(report["sources"]["fork"]["key"]["refs"]["refs/tags/carry/1.1.1zi-jz2"],
                         "d952ab0f7d08d52ce12ee3177fe2b503e8263806")

    def test_fork_carry_head_push_is_information(self):
        fork = ("8c7686b85b2f52ca453935e110d538d359daaed3\trefs/heads/1.1.1zi-carry\n"
                "bb2db0fee8ff0bc5d890beeffa086124637e67f2\trefs/heads/tools\n"
                "fb26261ef6aa8f1b3867f1a32e9a2a0d80057051\trefs/tags/tarball/1.1.1zi\n")
        code, report, _ = self.run_watch(self.baseline(), responses(fork=fork))
        self.assertEqual(code, 0, report)
        self.assertEqual(report["sources"]["fork"]["info"]["heads"]["refs/heads/tools"][:8], "bb2db0fe")

    def test_unreachable_source_is_exit_2_and_other_changes_still_reported(self):
        c = [{"sha": "e" * 40, "commit": {"committer": {"date": "2026-10-20T00:00:00Z"}, "message": "x"}}]
        code, report, _ = self.run_watch(self.baseline(), responses(cpanel=c, drop=[w.KZ_TAGS]))
        self.assertEqual(code, 2)
        self.assertEqual([e["source"] for e in report["errors"]], ["kzalewski"])
        self.assertEqual([c["source"] for c in report["changed"]], ["cpanel"])

    def test_only_subset_keeps_other_state(self):
        base = self.baseline()
        code, report, state = self.run_watch(base, responses(), only={"fork"})
        self.assertEqual(code, 0)
        self.assertEqual(report["unchanged"], ["fork"])
        self.assertEqual(state["sources"]["al2"], base["sources"]["al2"])

    def test_refuses_plain_http(self):
        with self.assertRaises(w.FetchError):
            w.Fetcher().get("http://example.invalid/")

    def test_version_order(self):
        vs = ["1.1.1zj", "1.1.1w", "1.1.1za", "1.1.1zi", "1.1.1c", "1.1.1g"]
        self.assertEqual(sorted(vs, key=w.version_key), ["1.1.1c", "1.1.1g", "1.1.1w", "1.1.1za", "1.1.1zi", "1.1.1zj"])

    def test_state_change_needs_review(self):
        # a changed run returns the new state for review; it never rewrites the reviewed one
        base = self.baseline()
        before = copy.deepcopy(base)
        self.run_watch(base, responses(kz_tags=["1.1.1zi"]))
        self.assertEqual(base, before)


class CommittedStateTests(unittest.TestCase):
    def test_reviewed_state(self):
        state = json.loads((REPO / "watch-state.json").read_text())
        self.assertEqual(state["schema"], w.SCHEMA)
        self.assertEqual(sorted(state["sources"]), sorted(w.SOURCES))
        # the committed state already expects U5's signed release tag
        self.assertEqual(state["sources"]["fork"]["key"]["refs"]["refs/tags/carry/1.1.1zi-jz2"],
                         "d952ab0f7d08d52ce12ee3177fe2b503e8263806")


if __name__ == "__main__":
    unittest.main()
