#!/usr/bin/env python3
"""Re-import OpenSSL's 1.1.1 release tarballs into git and compare the result with the published fork (B08).

Curated from the lab builder `.local/openssl-mirror/build_mirror.py` (docs/research/openssl-111-mirror-project.md)
for step L11 of docs/research/openssl-continued-readiness-plan.md. The `tools` branch of the fork carries it
as `tools/build_mirror.py`, next to the importer (`tools/import_release.py` = scripts/openssl_mirror_import.py).
Nothing here contacts a router, creates a repository on a server or pushes.

Build (deterministic; the same inputs always give the same commit ids):

  MIRROR_DL=DL MIRROR_REPO=REPO openssl_mirror_build.py [--dl DL] [--repo REPO] [--result OUT.json]

    REPO is a git work tree that holds OpenSSL's upstream objects (`--fetch-upstream` gets them). DL holds
    the inputs, all hash-checked against the pins below:
      srpm/openssl11-1.1.1{za,zb,zd,zf,zg,zh,zi}-1.amzn2.0.1.src.rpm   Amazon Linux 2 source RPMs
      openssl-1.1.1w.tar.gz                                             openssl.org (GPG-checked separately)
      openssl-1.1.1zX.tar.*                                            optional: extracted from the SRPM if absent
      carry/0001-*.patch, carry/0002-*.patch                            optional: rebuilds carry/1.1.1zi-jz1
      keys/amazon-linux-2-<fingerprint>.asc                             or MIRROR_KEYS, or ../keys next to this file
    It writes branches `tarballs`, `OpenSSL_1_1_1-continued` (tags tarball/1.1.1zX) and, with the carry
    patches, `1.1.1zi-carry` (tag carry/1.1.1zi-jz1). --result writes every commit id, tree and tag.

  openssl_mirror_build.py --fetch-upstream SOURCE --repo REPO
    fetch the three upstream objects the import needs (OpenSSL_1_1_1w, the public-by-SHA tip b78ec082 and
    4191043c36) from SOURCE (https://github.com/openssl/openssl.git or a local clone) into REPO, depth 1.

Compare:

  openssl_mirror_build.py --compare RESULT.json --refs LS-REMOTE.txt [--repo GITDIR]

    LS-REMOTE.txt is `git ls-remote` output of the published fork. Exit 0 only if every published
    `tarball/*` tag and `OpenSSL_1_1_1-continued` equal the re-imported commit ids. Carry tags
    (`carry/*`) that the importer rebuilds are checked by tree, not id, against the published commit
    object, which must be in GITDIR (default: the result's repo). Exit 1 on any difference or missing ref.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:  # lab name, then the name on the fork's tools branch
    import openssl_mirror_import as mi  # noqa: E402
except ImportError:  # pragma: no cover - tools branch layout
    import import_release as mi  # noqa: E402

IMPORTER = ("JohnsterID", "69278611+JohnsterID@users.noreply.github.com")
AL2_KEY = "99E617FE5DB527C0D8BD5F8E11CF1F95C87F5B1A"
OPENSSL_W_KEY = "EFC0A467D613CB83C7ED6D30D894E2CE8B3D79F5"
# The SRPMS mirror path recorded in the published import commit messages (30 Sep 2026). It is part of
# those commits, so it stays as recorded: changing it would change every commit id. Downloads must not use
# it: resolve https://cdn.amazonlinux.com/2/core/latest/SRPMS/mirror.list on every run (on 9 Oct it gave
# 3fc0e197...), or use the content-addressed blobstore URL https://cdn.amazonlinux.com/blobstore/<sha256>/<srpm>.
AL2_MIRROR_RECORDED = ("https://cdn.amazonlinux.com/2/core/2.0/SRPMS/"
                       "4f8fa06cd2aae03f75376d4f686e3f2d75ccd73ade02131072abdefd9ce64bbf/")
TAG_W = "e04bd3433fd84e1861bf258ea37928d9845e6a86"      # OpenSSL_1_1_1w (tag object signed by Tomas Mraz)
STABLE_HEAD = "b372b1f76450acdfed1e2301a39810146e28b02c"  # OpenSSL_1_1_1-stable, "Prepare for 1.1.1x"
# OpenSSL's own 1.1.1 commits after b372b1f, on no public ref but fetchable by SHA from github.com/openssl/openssl:
# through 1.1.1x (63ae3a7b) and 1.1.1y (c1476697) to "Fix SSL_select_next_proto" (CVE-2024-5535, first za fix).
PUBLIC_TIP = "b78ec0824da857223486660177d3b1f255c65d87"
CARRY1_UPSTREAM = "4191043c36f1a50c717a2d0075fc6f3b9bc0afc5"
CONTINUED = ["za", "zb", "zd", "zf", "zg", "zh", "zi"]
SUFFIX = "-jz1"  # "+jz1" breaks util/mkdef.pl, whose parser needs "-" or " " after the letters
CARRY_DATE = "2026-09-30T21:30:00+10:00"

# Pins (the same values as releases.json on the tools branch).
PINS = {
    "w": {"tarball": "openssl-1.1.1w.tar.gz",
          "tarball_sha256": "cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8"},
    "za": {"srpm_sha256": "c63113952dd1fddf2b56fe297c721fda92bb35859ff1a2715da56fa26bbb93cb",
           "tarball": "openssl-1.1.1za.tar.xz",
           "tarball_sha256": "d3a4439692dc9c9a828252b10dd85502b5b9bc9ab1ead54721e0bd1f6a72c074"},
    "zb": {"srpm_sha256": "3b3619602474b10371e0355930c769bb048767966febeda0080e9839b3913180",
           "tarball": "openssl-1.1.1zb.tar.gz",
           "tarball_sha256": "f17cf13df642e45809fd9b635fed5cde9e0b95f64b1a0d0d4874b8208cb661ff"},
    "zd": {"srpm_sha256": "cd2747ed6a640eb6668c5b99f029de97b347b97520e9be72b4e1f6ae90e92056",
           "tarball": "openssl-1.1.1zd.tar.gz",
           "tarball_sha256": "c1d619a8c61306d373b5f5b50a1939c8238f7c8e38cd6b45596308f23194945d"},
    "zf": {"srpm_sha256": "49c4e7ee406c755789799665d0e87aabb9c275806ec694139b65a03137e30879",
           "tarball": "openssl-1.1.1zf.tar.gz",
           "tarball_sha256": "8bd7a2e78d2404485c4a6e9db78ccdcbd552c30663b43000763a898624f58bf9"},
    "zg": {"srpm_sha256": "b565c944c4d9e25c251b24ff287ab558b22d30d39acbb28d4204cd27c2b944a6",
           "tarball": "openssl-1.1.1zg.tar.gz",
           "tarball_sha256": "8823d2c45550819e1618f704a384cf79698cbffb3884e2760935bdffbc3b2270"},
    "zh": {"srpm_sha256": "75a308ebd087c03400ca0885741d4f278a980d17f7e515582a5966499e1161be",
           "tarball": "openssl-1.1.1zh.tar.gz",
           "tarball_sha256": "89ade77ad61cb264ad5f2a67caf18b291cb4fce22f608c834a6b0e091c599fc2"},
    "zi": {"srpm_sha256": "5790d70cd5f66704ec6acb14119610cc3d522255f7700e16ad7d3d721f543fef",
           "tarball": "openssl-1.1.1zi.tar.gz",
           "tarball_sha256": "64f0f77354f10a8e5012e44887a7af82581a57378cfc446fc0da1fa74c1dae5a"},
}


class BuildError(RuntimeError):
    pass


def run(repo, *args, env=None, input_text=None):
    r = subprocess.run(list(args), cwd=repo, env=env, capture_output=True, text=True, input=input_text)
    if r.returncode:
        raise BuildError(f"{args}: {r.stderr[-800:]}")
    return r.stdout.strip()


def srpm_name(v):
    return f"openssl11-1.1.1{v}-1.amzn2.0.1.src.rpm"


class Inputs:
    """The download directory (MIRROR_DL): every file is checked against PINS before use."""

    def __init__(self, dl, keys=None):
        self.dl = Path(dl).resolve()
        cands = [Path(keys)] if keys else []
        cands += [self.dl / "keys", HERE.parent / "keys"]
        self.key = next((c / f"amazon-linux-2-{AL2_KEY}.asc" for c in cands
                         if (c / f"amazon-linux-2-{AL2_KEY}.asc").exists()), None)
        self._srpm, self._tar = {}, {}
        self.work = Path(tempfile.mkdtemp(prefix="mirror-dl-"))

    def srpm(self, v):
        """rpm-verify result of the pinned SRPM; both Amazon signatures must verify."""
        if v not in self._srpm:
            path = self.dl / "srpm" / srpm_name(v)
            if not path.exists():
                raise BuildError(f"missing input {path}")
            if self.key is None:
                raise BuildError(f"Amazon Linux 2 key amazon-linux-2-{AL2_KEY}.asc not found (MIRROR_KEYS)")
            info = mi.rpm_verify(path, key=self.key, expect_sha256=PINS[v]["srpm_sha256"])
            if info.get("rsa_header_signer") != AL2_KEY or info.get("pgp_header_payload_signer") != AL2_KEY:
                raise BuildError(f"{path}: not signed by {AL2_KEY}")
            self._srpm[v] = info
        return self._srpm[v]

    def tarball(self, v):
        if v not in self._tar:
            name = PINS[v]["tarball"]
            cands = [self.dl / name, self.dl / "tarballs" / name]
            path = next((c for c in cands if c.exists()), None)
            if path is None and v != "w":
                self.srpm(v)
                path = self.work / name
                mi.rpm_extract(self.dl / "srpm" / srpm_name(v), name, path)
            if path is None:
                raise BuildError(f"missing input {cands[0]}")
            got = mi.sha256_file(path)
            if got != PINS[v]["tarball_sha256"]:
                raise BuildError(f"{path}: sha256 {got} != pinned {PINS[v]['tarball_sha256']}")
            self._tar[v] = path
        return self._tar[v]

    def carry_patches(self):
        d = self.dl / "carry"
        p1, p2 = sorted(d.glob("0001-*.patch")), sorted(d.glob("0002-*.patch"))
        return (p1[0], p2[0]) if p1 and p2 else None


def changes_sections(tarball):
    """[(from, to, date, text)] from the CHANGES file inside a release tarball."""
    with tarfile.open(tarball, "r:*") as tf:
        member = next(m for m in tf.getmembers() if m.isfile() and m.name.count("/") == 1
                      and m.name.endswith("/CHANGES"))
        text = tf.extractfile(member).read().decode(errors="replace")
    heads = list(re.finditer(r"^ Changes between (\S+) and (\S+) \[([^\]]+)\]\s*$", text, re.M))
    out = []
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        out.append((m.group(1), m.group(2), m.group(3), text[m.end():end]))
    return out


def release_message(inputs, v, prev):
    tb = inputs.tarball(v)
    covered, ids = [], []
    for _frm, to, date, body in changes_sections(tb):
        if to == f"1.1.1{prev}":
            break
        covered.append(f"{to} [{date}]")
        ids += re.findall(r"CVE-\d{4}-\d+", body)
    ids = sorted(set(ids), key=lambda c: (int(c.split("-")[1]), int(c.split("-")[2])))
    lines = [f"OpenSSL 1.1.1{v} (release tarball import)", "",
             f"Tree = the content of OpenSSL's {tb.name}, unmodified."]
    if len(covered) > 1:
        missing = ", ".join(c.split(" ")[0] for c in reversed(covered[1:]))
        lines.append(f"No public tarball exists for {missing}; their changes are folded into this commit.")
    lines += ["", "CHANGES sections covered: " + "; ".join(reversed(covered)),
              "Advisories listed: " + (", ".join(ids) if ids else "none"), ""]
    if v == "w":
        lines += ["Source: https://www.openssl.org/source/openssl-1.1.1w.tar.gz",
                  f"Signature: openssl-1.1.1w.tar.gz.asc, valid, key {OPENSSL_W_KEY}",
                  "Equals `git archive OpenSSL_1_1_1w` file for file; this commit only drops the",
                  "export-ignored paths (fuzz corpora, .github, submodules).", ""]
    else:
        s = inputs.srpm(v)
        with tarfile.open(tb, "r:*") as tf:
            owners = {(m.uname, m.gname) for m in tf.getmembers()}
        repack = ""
        if owners != {("root", "root")} or tb.suffix == ".xz":
            repack = (f"Note: this tarball was repacked by Amazon (member owner {sorted(owners)[0][0]}"
                      + (", xz-recompressed" if tb.suffix == ".xz" else "") +
                      "); its byte hash is not OpenSSL's, only its content is imported.")
        built = datetime.datetime.fromtimestamp(s["buildtime"], datetime.timezone.utc)
        lines += [f"Source-RPM: {s['file']} (Amazon Linux 2 core, {AL2_MIRROR_RECORDED})",
                  f"Source-RPM-SHA256: {s['sha256']}",
                  f"Source-RPM-Signature: RSA header + PGP header/payload valid, key {AL2_KEY}",
                  f"Source-RPM-Buildtime: {built:%Y-%m-%dT%H:%M:%SZ}"]
        if repack:
            lines.append(repack)
        lines.append("")
    lines += [f"Tarball: {tb.name}", f"Tarball-SHA256: {mi.sha256_file(tb)}"]
    return "\n".join(lines) + "\n"


def ensure_repo(repo):
    if not (Path(repo) / ".git").exists():
        raise BuildError(f"{repo}: not a git work tree (git init, then --fetch-upstream)")
    for obj in (TAG_W, PUBLIC_TIP):
        if subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"{obj}^{{commit}}"],
                          capture_output=True).returncode:
            raise BuildError(f"{repo}: upstream commit {obj} missing (--fetch-upstream)")
    run(repo, "git", "config", "user.name", IMPORTER[0])
    run(repo, "git", "config", "user.email", IMPORTER[1])
    run(repo, "git", "config", "commit.gpgsign", "false")


def fetch_upstream(repo, source):
    """Depth-1 fetch of the three upstream objects by id (GitHub serves reachable objects by SHA)."""
    repo = Path(repo)
    if not (repo / ".git").exists():
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
    wants = [TAG_W, PUBLIC_TIP, CARRY1_UPSTREAM]
    run(repo, "git", "-c", "uploadpack.allowAnySHA1InWant=true", "fetch", "-q", "--no-tags", "--depth=1",
        source, *wants)
    run(repo, "git", "update-ref", "refs/upstream/OpenSSL_1_1_1w", TAG_W)
    run(repo, "git", "update-ref", "refs/upstream/public-tip", PUBLIC_TIP)
    run(repo, "git", "update-ref", "refs/upstream/4191043c36", CARRY1_UPSTREAM)
    return {"fetched": wants}


def import_branches(repo, inputs):
    results = {}
    rels, prev = [], None
    for v in ["w"] + CONTINUED:
        tb = inputs.tarball(v)
        rels.append({"version": f"1.1.1{v}", "tarball": str(tb), "tarball_sha256": mi.sha256_file(tb),
                     "message": release_message(inputs, v, prev) if v != "w" else release_message(inputs, "w", "v")})
        prev = v
    man = {"author": IMPORTER[0], "email": IMPORTER[1], "tz": "+0000", "parent": TAG_W, "branch": "tarballs",
           "releases": rels}
    results["tarballs"] = mi.import_releases(repo, man)
    rels2 = []
    for r in rels[1:]:
        r2 = dict(r, tag=f"tarball/{r['version']}")
        if r["version"] == "1.1.1za":
            r2["message"] = r["message"].replace(
                "No public tarball exists for 1.1.1x, 1.1.1y; their changes are folded into this commit.",
                "Parent: b78ec0824da8 \"Fix SSL_select_next_proto\", an OpenSSL commit (not on any public\n"
                "ref; fetched by SHA from github.com/openssl/openssl), whose ancestors are the 1.1.1x\n"
                "(63ae3a7b02f8) and 1.1.1y (c14766976d2d) release commits. This commit adds the rest of 1.1.1za.")
        rels2.append(r2)
    man2 = {"author": IMPORTER[0], "email": IMPORTER[1], "tz": "+0000", "parent": PUBLIC_TIP,
            "branch": "OpenSSL_1_1_1-continued", "keep_export_ignored": True, "releases": rels2}
    results["OpenSSL_1_1_1-continued"] = mi.import_releases(repo, man2)
    checks = []
    for r, res in zip(rels, results["tarballs"]):
        checks.append(dict(mi.tree_check(repo, res["commit"], r["tarball"]), branch="tarballs"))
    for r, res in zip(rels2, results["OpenSSL_1_1_1-continued"]):
        checks.append(dict(mi.tree_check(repo, res["commit"], r["tarball"], archive_mode=True),
                           branch="OpenSSL_1_1_1-continued"))
    results["tree_checks"] = checks
    return results


CARRY1_MSG_TAIL = """(cherry picked from commit 4191043c36f1a50c717a2d0075fc6f3b9bc0afc5)

[Carried on OpenSSL 1.1.1zi: OpenSSL's own 1.1.1za-1.1.1zi contain only the
 first CVE-2025-69419 fix (3.0 41be0f216404), so OPENSSL_uni2utf8() still
 returns NULL for BMP strings with characters that need three UTF-8 bytes
 (for example U+2192, U+20AC). test/asn1_internal_test.c conflicted and the
 new test was registered by hand; the crypto/pkcs12/p12_utl.c hunk applied
 unchanged. Drop this commit if a later official 1.1.1 release carries it.]
"""

CARRY2_MSG = """Defer computation of relative CRLDP names (CVE-2026-35189), 1.1.1 port

Lab port, not a cherry-pick: OpenSSL's 1.1.1 fix for CVE-2026-35189 is in the
1.1.1zj (29 Sep 2026), which has no public source. This re-does upstream
c72ae182cac17a82e4246c6ecd4e9c4ec3586ec9 ("Defer computation of relative CRLDP
names", Viktor Dukhovni, openssl-3.4 branch, merged 2026-09-29) for 1.1.1:

 - crypto/x509/v3_{crld,purp}.c -> crypto/x509v3/ paths;
 - 1.1.1's X509_NAME_dup() takes a non-const name;
 - 1.1.1 has no ERR_raise context and no invalid-distpoint check in setup_dp();
 - ossl_dist_point_name_full() stays internal (no new export).

A 16 KB certificate with 400 nameRelativeToCRLIssuer distribution points makes
X509_check_purpose() hold 6.35 MB on 1.1.1zi and 94 KB with this change.
Not reviewed by OpenSSL. Replace with OpenSSL's 1.1.1zj code if it becomes
public.

Based-on: c72ae182cac17a82e4246c6ecd4e9c4ec3586ec9
"""

VERSION_MSG = """Mark the version text as 1.1.1zi{suffix}

OPENSSL_VERSION_TEXT becomes "OpenSSL 1.1.1zi{suffix}  30 Sep 2026" so this
build can be told apart from OpenSSL's own 1.1.1zi (which lacks the two
commits above). OPENSSL_VERSION_NUMBER stays 0x1010122fL and the shared
library version stays 1.1, so the ABI and version checks of consumers are
unchanged. Scanners that parse "OpenSSL 1.1.1zi" still see the release this
is based on, which is the truth for every fix except the two carried ones.

The suffix uses "-", the separator of OpenSSL's own "-dev"/"-pre"/"-fips"
suffixes: util/mkdef.pl parses the text with
/OPENSSL_VERSION_TEXT\\s+"OpenSSL (\\d\\.\\d\\.)(\\d[a-z]*)(-| )/ and stops the build
("Can't find OpenSSL version number") on a "+" suffix.
"""

CHANGES_ENTRY = (" Changes between 1.1.1zi and 1.1.1zi{suffix} [30 Sep 2026]\n\n"
                 " *) Completed the fix for CVE-2025-69419: OPENSSL_uni2utf8() and\n"
                 "    PKCS12 friendly names now convert BMP strings with characters\n"
                 "    that need three UTF-8 bytes instead of failing.\n"
                 "    (CVE-2025-69419)\n"
                 "    [Bernd Edlinger; carried from openssl-3.0 4191043c36]\n\n"
                 " *) Relative CRL distribution point names are computed only when a\n"
                 "    CRL is checked, not when a certificate's extensions are cached.\n"
                 "    (CVE-2026-35189)\n"
                 "    [1.1.1 port of Viktor Dukhovni's c72ae182ca; not reviewed by OpenSSL]\n\n")


def carry_branch(repo, zi_commit, patches):
    env = dict(os.environ, GIT_COMMITTER_NAME=IMPORTER[0], GIT_COMMITTER_EMAIL=IMPORTER[1],
               GIT_COMMITTER_DATE=CARRY_DATE)
    run(repo, "git", "checkout", "-q", "-f", "-B", "1.1.1zi-carry", zi_commit)
    run(repo, "git", "clean", "-qfdx")
    up = run(repo, "git", "log", "-1", "--format=%an%x00%ae%x00%aD%x00%B", CARRY1_UPSTREAM)
    an, ae, ad, body = up.split("\x00", 3)
    run(repo, "git", "apply", "--index", str(patches[0]))
    e1 = dict(env, GIT_AUTHOR_NAME=an, GIT_AUTHOR_EMAIL=ae, GIT_AUTHOR_DATE=ad)
    run(repo, "git", "commit", "-q", "--no-verify", "--no-gpg-sign", "-F", "-", env=e1,
        input_text=body.rstrip() + "\n" + CARRY1_MSG_TAIL)
    run(repo, "git", "apply", "--index", str(patches[1]))
    e2 = dict(env, GIT_AUTHOR_NAME=IMPORTER[0], GIT_AUTHOR_EMAIL=IMPORTER[1], GIT_AUTHOR_DATE=CARRY_DATE)
    run(repo, "git", "commit", "-q", "--no-verify", "--no-gpg-sign", "-F", "-", env=e2, input_text=CARRY2_MSG)
    carry2 = run(repo, "git", "rev-parse", "HEAD")
    hdr = Path(repo) / "include/openssl/opensslv.h"
    t = hdr.read_text()
    new = t.replace('"OpenSSL 1.1.1zi  25 Aug 2026"', f'"OpenSSL 1.1.1zi{SUFFIX}  30 Sep 2026"')
    if new == t:
        raise BuildError("opensslv.h: 1.1.1zi version text not found")
    hdr.write_text(new)
    ch = Path(repo) / "CHANGES"
    c = ch.read_text()
    marker = " Changes between 1.1.1zh and 1.1.1zi [25 Aug 2026]"
    if marker not in c:
        raise BuildError("CHANGES: 1.1.1zi section not found")
    ch.write_text(c.replace(marker, CHANGES_ENTRY.format(suffix=SUFFIX) + marker, 1))
    run(repo, "git", "add", "include/openssl/opensslv.h", "CHANGES")
    run(repo, "git", "commit", "-q", "--no-verify", "--no-gpg-sign", "-F", "-", env=e2,
        input_text=VERSION_MSG.format(suffix=SUFFIX))
    head = run(repo, "git", "rev-parse", "HEAD")
    run(repo, "git", "tag", "-f", f"carry/1.1.1zi{SUFFIX}", head)
    return {"carry_0001": run(repo, "git", "rev-parse", "HEAD~2"), "carry_0002": carry2, "version_commit": head}


def build(repo, dl, keys=None):
    repo = Path(repo).resolve()
    ensure_repo(repo)
    inputs = Inputs(dl, keys)
    res = import_branches(repo, inputs)
    if not all(c["equal"] for c in res["tree_checks"]):
        raise BuildError("an imported tree differs from its tarball")
    tags, heads = {}, {}
    for branch in ("tarballs", "OpenSSL_1_1_1-continued"):
        heads[branch] = res[branch][-1]["commit"]
        for r in res[branch]:
            if r.get("tag"):
                tags[r["tag"]] = r["commit"]
    patches = inputs.carry_patches()
    carry = None
    if patches:
        carry = carry_branch(repo, heads["OpenSSL_1_1_1-continued"], patches)
        tags[f"carry/1.1.1zi{SUFFIX}"] = carry["version_commit"]
        heads["1.1.1zi-carry"] = carry["version_commit"]
    trees = {ref: run(repo, "git", "rev-parse", f"{sha}^{{tree}}") for ref, sha in {**tags, **heads}.items()}
    return {"schema": "openssl-mirror-build-result/1", "repo": str(repo),
            "upstream": {"OpenSSL_1_1_1w": TAG_W, "public_tip": PUBLIC_TIP},
            "heads": heads, "tags": tags, "trees": trees,
            "imports": {b: [{k: r[k] for k in ("version", "commit", "tree", "tag", "date_epoch")} for r in res[b]]
                        for b in ("tarballs", "OpenSSL_1_1_1-continued")},
            "carry": carry, "carry_skipped": None if patches else "no carry/0001-*.patch and 0002-*.patch in MIRROR_DL",
            "tree_checks": [{k: c[k] for k in ("branch", "rev", "tarball", "mode", "files", "equal")}
                            for c in res["tree_checks"]]}


# --------------------------------------------------------------------------------------------- compare

def parse_ls_remote(text):
    """{ref: commit id}; an annotated tag's peeled line (ref^{}) replaces the tag object id."""
    refs, peeled = {}, {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sha, ref = line.split(None, 1)
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError(f"not a ls-remote line: {line!r}")
        if ref.endswith("^{}"):
            peeled[ref[:-3]] = sha
        else:
            refs[ref] = sha
    refs.update(peeled)
    return refs


def tree_of(gitdir, sha):
    r = subprocess.run(["git", "-C", str(gitdir), "rev-parse", "--verify", "-q", f"{sha}^{{tree}}"],
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def compare(result, published, gitdir=None):
    """Check a build result against published refs. Returns (ok, report)."""
    checks, problems = [], []
    tags, heads = result["tags"], result["heads"]

    def add(ref, status, **kw):
        checks.append(dict(ref=ref, status=status, **kw))
        if status not in ("equal", "tree-equal", "unpublished", "not-rebuilt"):
            problems.append(ref)

    key = "refs/heads/OpenSSL_1_1_1-continued"
    if key not in published:
        add(key, "missing-published")
    elif "OpenSSL_1_1_1-continued" not in heads:
        add(key, "missing-rebuilt", published=published[key])
    else:
        same = published[key] == heads["OpenSSL_1_1_1-continued"]
        add(key, "equal" if same else "differs", published=published[key], rebuilt=heads["OpenSSL_1_1_1-continued"])
    pub_tarballs = sorted(r for r in published if r.startswith("refs/tags/tarball/"))
    if not pub_tarballs:
        add("refs/tags/tarball/*", "missing-published")
    for ref in pub_tarballs:
        name = ref[len("refs/tags/"):]
        if name not in tags:
            add(ref, "missing-rebuilt", published=published[ref])
        else:
            add(ref, "equal" if tags[name] == published[ref] else "differs", published=published[ref],
                rebuilt=tags[name])
    for name in sorted(t for t in tags if t.startswith("tarball/")):
        if f"refs/tags/{name}" not in published:
            add(f"refs/tags/{name}", "unpublished", rebuilt=tags[name])
    gitdir = gitdir or result.get("repo")
    for ref in sorted(r for r in published if r.startswith("refs/tags/carry/")):
        name = ref[len("refs/tags/"):]
        if name not in tags:
            add(ref, "not-rebuilt", published=published[ref])
            continue
        rebuilt_tree = result["trees"].get(name)
        pub_tree = tree_of(gitdir, published[ref]) if gitdir else None
        if pub_tree is None:
            add(ref, "published-object-missing", published=published[ref])
        else:
            add(ref, "tree-equal" if pub_tree == rebuilt_tree else "tree-differs", published=published[ref],
                rebuilt=tags[name], tree=rebuilt_tree, published_tree=pub_tree, same_id=tags[name] == published[ref])
    return not problems, {"ok": not problems, "problems": problems, "checks": checks}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=os.environ.get("MIRROR_REPO"))
    ap.add_argument("--dl", default=os.environ.get("MIRROR_DL"))
    ap.add_argument("--keys", default=os.environ.get("MIRROR_KEYS"))
    ap.add_argument("--result", type=Path, help="write the build result (commit ids, trees, tags) here")
    ap.add_argument("--fetch-upstream", metavar="SOURCE")
    ap.add_argument("--compare", type=Path, metavar="RESULT")
    ap.add_argument("--refs", type=Path, metavar="LS_REMOTE")
    a = ap.parse_args(argv)
    if a.compare:
        if not a.refs:
            ap.error("--compare needs --refs")
        result = json.loads(a.compare.read_text())
        ok, report = compare(result, parse_ls_remote(a.refs.read_text()), a.repo)
        print(json.dumps(report, indent=1))
        return 0 if ok else 1
    if not a.repo:
        ap.error("--repo or MIRROR_REPO is required")
    if a.fetch_upstream:
        print(json.dumps(fetch_upstream(a.repo, a.fetch_upstream), indent=1))
        return 0
    if not a.dl:
        ap.error("--dl or MIRROR_DL is required")
    res = build(a.repo, a.dl, a.keys)
    if a.result:
        a.result.write_text(json.dumps(res, indent=1) + "\n")
    print(json.dumps({"tree_checks_equal": all(c["equal"] for c in res["tree_checks"]),
                      "heads": res["heads"], "tags": res["tags"]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
