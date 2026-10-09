#!/usr/bin/env python3
"""Weekly watch of the sources that openssl-1.1.1-continued follows (B08, readiness plan step L12).

The fork's `tools` branch carries this file as `tools/watch.py`; its `upstream-watch.yml` (on the default
branch) runs it every Monday, and the lab runs the same script in its sessions as a backup for GitHub's
60-day schedule disable. Standard library only, so it runs under `python3 -I`. It only reads: HTTPS GETs
and `git ls-remote`. It never pushes, posts or writes anywhere except the files named by --report and
--write-state.

Sources (each becomes one entry of the state):
  al2        Amazon Linux 2 core SRPMS: mirror.list -> repodata/repomd.xml (revision) -> primary.xml.gz
             (sha256 checked against repomd) -> every `openssl11` source package. A change is a new or
             removed openssl11 version; the repomd revision and mirror path alone are informational.
  secadv     https://openssl-library.org/news/secadv/: the newest advisory file name and its sha256.
  vulns111   https://openssl-library.org/news/vulnerabilities-1.1.1/: the CVE ids and 1.1.1zX names on it.
  cpanel     CpanelInc/ea-openssl11: the newest commit (GitHub API).
  kzalewski  kzalewski/openssl-1.1.1: pushed_at and the tag names (GitHub API).
  fork       JohnsterID/openssl-1.1.1-continued: `git ls-remote`; every tag (peeled) and OpenSSL_1_1_1-continued
             must match; the carry, ci and tools heads are reported as information.

Exit status: 0 nothing changed; 1 something changed (the CI run stays red until a reviewed state is
committed: run with --write-state, review the diff, commit watch-state.json); 2 a source could not be
fetched or parsed (changes found in other sources are still reported).

  watch.py --state watch-state.json [--report REPORT.json] [--write-state NEW.json] [--only al2,fork]
  watch.py --fixtures DIR ...        read every response from DIR (offline; tests and dry runs)
  watch.py --save-fixtures DIR ...   also save every response to DIR

GITHUB_TOKEN (read-only) is sent to api.github.com only, to raise the rate limit.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

SCHEMA = "openssl-upstream-watch/1"
AL2_MIRRORLIST = "https://cdn.amazonlinux.com/2/core/latest/SRPMS/mirror.list"
SECADV_INDEX = "https://openssl-library.org/news/secadv/"
VULNS_111 = "https://openssl-library.org/news/vulnerabilities-1.1.1/"
CPANEL_COMMITS = "https://api.github.com/repos/CpanelInc/ea-openssl11/commits?per_page=1"
KZ_REPO = "https://api.github.com/repos/kzalewski/openssl-1.1.1"
KZ_TAGS = "https://api.github.com/repos/kzalewski/openssl-1.1.1/tags?per_page=100"
FORK = "https://github.com/JohnsterID/openssl-1.1.1-continued.git"
SOURCES = ("al2", "secadv", "vulns111", "cpanel", "kzalewski", "fork")
REPO_NS = {"r": "http://linux.duke.edu/metadata/repo"}
COMMON_NS = {"c": "http://linux.duke.edu/metadata/common"}
USER_AGENT = "openssl-1.1.1-continued-watch/1"
MAX_BYTES = 64 << 20


class FetchError(RuntimeError):
    pass


def fixture_name(url):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", url)[:180]


class Fetcher:
    """HTTPS GETs and git ls-remote, or the same answers from a fixture directory."""

    def __init__(self, fixtures=None, save=None, token=None, timeout=60):
        self.fixtures = Path(fixtures) if fixtures else None
        self.save = Path(save) if save else None
        self.token = token
        self.timeout = timeout
        if self.save:
            self.save.mkdir(parents=True, exist_ok=True)

    def _fixture(self, key):
        path = self.fixtures / fixture_name(key)
        if not path.exists():
            raise FetchError(f"no fixture for {key} ({path.name})")
        return path.read_bytes()

    def _keep(self, key, data):
        if self.save:
            (self.save / fixture_name(key)).write_bytes(data)
        return data

    def get(self, url):
        if self.fixtures:
            return self._fixture(url)
        if not url.startswith("https://"):
            raise FetchError(f"refusing a non-HTTPS URL: {url}")
        headers = {"User-Agent": USER_AGENT}
        if url.startswith("https://api.github.com/"):
            headers["Accept"] = "application/vnd.github+json"
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = r.read(MAX_BYTES + 1)
        except (urllib.error.URLError, OSError) as e:
            raise FetchError(f"GET {url}: {e}") from e
        if len(data) > MAX_BYTES:
            raise FetchError(f"GET {url}: larger than {MAX_BYTES} bytes")
        return self._keep(url, data)

    def ls_remote(self, url):
        key = "ls-remote " + url
        if self.fixtures:
            return self._fixture(key).decode()
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        r = subprocess.run(["git", "ls-remote", url], capture_output=True, timeout=self.timeout, env=env)
        if r.returncode:
            raise FetchError(f"git ls-remote {url}: {r.stderr.decode(errors='replace').strip()[-300:]}")
        return self._keep(key, r.stdout).decode()


# ------------------------------------------------------------------------------------------- parsers

def version_key(ver):
    """Order OpenSSL 1.1.1 versions: 1.1.1w < 1.1.1z < 1.1.1za < 1.1.1zj."""
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)([a-z]*)", ver)
    if not m:
        return (0, 0, 0, 0, ver)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), len(m.group(4)), m.group(4))


def release_key(rel):
    return tuple(int(x) if x.isdigit() else x for x in re.split(r"[.]", rel))


def parse_repomd(data):
    root = ET.fromstring(data)
    rev = root.findtext("r:revision", namespaces=REPO_NS)
    for d in root.findall("r:data", REPO_NS):
        if d.get("type") == "primary":
            cs = d.find("r:checksum", REPO_NS)
            loc = d.find("r:location", REPO_NS)
            return {"revision": int(rev) if rev and rev.isdigit() else rev, "primary_href": loc.get("href"),
                    "primary_sha256": cs.text.strip() if cs is not None and cs.get("type") == "sha256" else None}
    raise FetchError("repomd.xml has no primary data")


def parse_primary(data, name="openssl11"):
    """Every source package called `name`: [{version, release, sha256, location}], oldest first."""
    out = []
    root = ET.fromstring(gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data)
    for pkg in root.findall("c:package", COMMON_NS):
        if pkg.findtext("c:name", namespaces=COMMON_NS) != name:
            continue
        if pkg.findtext("c:arch", namespaces=COMMON_NS) != "src":
            continue
        v = pkg.find("c:version", COMMON_NS)
        loc = pkg.find("c:location", COMMON_NS)
        cs = pkg.find("c:checksum", COMMON_NS)
        out.append({"version": v.get("ver"), "release": v.get("rel"),
                    "sha256": cs.text.strip() if cs is not None else None,
                    "location": loc.get("href") if loc is not None else None})
    out.sort(key=lambda p: (version_key(p["version"]), release_key(p["release"])))
    return out


def parse_secadv_index(html):
    names = sorted(set(re.findall(r"\b(\d{8}[a-z]?\.txt)\b", html)))
    if not names:
        raise FetchError("no advisory file names in the secadv index")
    return names


def parse_vulns_page(html):
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", html)),
                  key=lambda c: (int(c.split("-")[1]), int(c.split("-")[2])))
    versions = sorted(set(re.findall(r"\b1\.1\.1[a-z]{1,2}\b", html)), key=version_key)
    if not cves:
        raise FetchError("no CVE ids on the 1.1.1 vulnerabilities page")
    return {"cves": cves, "versions": versions}


def parse_ls_remote(text):
    """{ref: id}; an annotated tag's peeled line (ref^{}) replaces the tag object id."""
    refs, peeled = {}, {}
    for line in text.splitlines():
        if line.strip():
            sha, ref = line.split(None, 1)
            ref = ref.strip()
            if ref.endswith("^{}"):
                peeled[ref[:-3]] = sha
            else:
                refs[ref] = sha
    refs.update(peeled)
    return dict(sorted(refs.items()))


def fork_key_ref(ref):
    """Refs that must not move without a reviewed state: every tag and the import branch. The carry,
    ci and tools heads move with ordinary pushes and are reported as information only."""
    return ref.startswith("refs/tags/") or ref == "refs/heads/OpenSSL_1_1_1-continued"


# --------------------------------------------------------------------------------------------- sources

def observe_al2(f):
    mirrors = [line.strip() for line in f.get(AL2_MIRRORLIST).decode().splitlines() if line.strip()]
    if not mirrors or not mirrors[0].startswith("https://"):
        raise FetchError("mirror.list gave no HTTPS mirror")
    base = mirrors[0].rstrip("/") + "/"
    repomd = parse_repomd(f.get(base + "repodata/repomd.xml"))
    primary = f.get(base + repomd["primary_href"])
    got = hashlib.sha256(primary).hexdigest()
    if repomd["primary_sha256"] and got != repomd["primary_sha256"]:
        raise FetchError(f"primary.xml.gz sha256 {got} != repomd {repomd['primary_sha256']}")
    pkgs = parse_primary(primary)
    if not pkgs:
        raise FetchError("no openssl11 source package in primary.xml")
    newest = pkgs[-1]
    return {"key": {"openssl11": sorted(f"{p['version']}-{p['release']}" for p in pkgs)},
            "info": {"mirror": base, "repomd_revision": repomd["revision"],
                     "newest": f"{newest['version']}-{newest['release']}", "newest_sha256": newest["sha256"],
                     "newest_location": newest["location"], "primary_sha256": got}}


def observe_secadv(f):
    names = parse_secadv_index(f.get(SECADV_INDEX).decode(errors="replace"))
    newest = names[-1]
    body = f.get(SECADV_INDEX + newest)
    return {"key": {"newest": newest, "sha256": hashlib.sha256(body).hexdigest()},
            "info": {"count": len(names), "names_1_1_1": "1.1.1" in body.decode(errors="replace")}}


def observe_vulns111(f):
    page = parse_vulns_page(f.get(VULNS_111).decode(errors="replace"))
    return {"key": page, "info": {"cve_count": len(page["cves"]), "newest_named": page["versions"][-1]
                                  if page["versions"] else None}}


def observe_cpanel(f):
    commits = json.loads(f.get(CPANEL_COMMITS))
    if not isinstance(commits, list) or not commits:
        raise FetchError("ea-openssl11 commits: unexpected answer")
    c = commits[0]
    return {"key": {"newest_commit": c["sha"]},
            "info": {"date": c["commit"]["committer"]["date"], "subject": c["commit"]["message"].splitlines()[0]}}


def observe_kzalewski(f):
    repo = json.loads(f.get(KZ_REPO))
    tags = json.loads(f.get(KZ_TAGS))
    if "pushed_at" not in repo or not isinstance(tags, list):
        raise FetchError("kzalewski: unexpected answer")
    return {"key": {"pushed_at": repo["pushed_at"], "tags": sorted(t["name"] for t in tags)},
            "info": {"default_branch": repo.get("default_branch")}}


def observe_fork(f):
    refs = parse_ls_remote(f.ls_remote(FORK))
    if not refs:
        raise FetchError("fork: empty ls-remote")
    return {"key": {"refs": {r: s for r, s in refs.items() if fork_key_ref(r)}},
            "info": {"heads": {r: s for r, s in refs.items() if not fork_key_ref(r)}, "count": len(refs)}}


OBSERVERS = {"al2": observe_al2, "secadv": observe_secadv, "vulns111": observe_vulns111,
             "cpanel": observe_cpanel, "kzalewski": observe_kzalewski, "fork": observe_fork}


def describe_change(src, old, new):
    """Short human text for a changed source."""
    if src == "al2":
        added = sorted(set(new["openssl11"]) - set(old.get("openssl11", [])))
        gone = sorted(set(old.get("openssl11", [])) - set(new["openssl11"]))
        zj = [v for v in added if version_key(v.split("-")[0]) > version_key("1.1.1zi")]
        text = f"openssl11 added {added or '-'} removed {gone or '-'}"
        return text + ("; NEW 1.1.1 RELEASE: run the zj reconciliation (event Z1)" if zj else "")
    if src == "fork":
        o, n = old.get("refs", {}), new["refs"]
        moved = sorted(r for r in set(o) | set(n) if o.get(r) != n.get(r))
        return "refs changed: " + ", ".join(moved)
    keys = sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))
    return "changed: " + ", ".join(keys)


def watch(state, fetcher, only=None):
    """Compare every source with the state. Returns (exit code, report, new state)."""
    old_sources = (state or {}).get("sources", {})
    report = {"schema": SCHEMA, "changed": [], "errors": [], "unchanged": [], "sources": {}}
    new_sources = {}
    for src in SOURCES:
        if only and src not in only:
            if src in old_sources:
                new_sources[src] = old_sources[src]
            continue
        try:
            obs = OBSERVERS[src](fetcher)
        except (FetchError, ValueError, KeyError, ET.ParseError, OSError, subprocess.SubprocessError) as e:
            report["errors"].append({"source": src, "error": str(e)[:400]})
            if src in old_sources:
                new_sources[src] = old_sources[src]
            continue
        new_sources[src] = obs
        old = old_sources.get(src)
        entry = {"key": obs["key"], "info": obs["info"]}
        if old is None:
            entry["status"] = "new"
            report["changed"].append({"source": src, "what": "no recorded state"})
        elif old.get("key") != obs["key"]:
            entry["status"] = "changed"
            report["changed"].append({"source": src, "what": describe_change(src, old["key"], obs["key"])})
        else:
            entry["status"] = "unchanged"
            report["unchanged"].append(src)
        report["sources"][src] = entry
    code = 2 if report["errors"] else (1 if report["changed"] else 0)
    report["exit"] = code
    report["verdict"] = {0: "unchanged", 1: "changed", 2: "fetch-error"}[code]
    return code, report, {"schema": SCHEMA, "sources": new_sources}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", type=Path, required=True, help="the reviewed state (watch-state.json)")
    ap.add_argument("--report", type=Path)
    ap.add_argument("--write-state", type=Path, help="write the observed state here, for review")
    ap.add_argument("--only", help="comma-separated subset of " + ",".join(SOURCES))
    ap.add_argument("--fixtures", type=Path)
    ap.add_argument("--save-fixtures", type=Path)
    a = ap.parse_args(argv)
    only = set(a.only.split(",")) if a.only else None
    if only and not only <= set(SOURCES):
        ap.error(f"unknown source in --only: {sorted(only - set(SOURCES))}")
    state = json.loads(a.state.read_text()) if a.state.exists() else None
    if state is not None and state.get("schema") != SCHEMA:
        ap.error(f"{a.state}: schema is not {SCHEMA}")
    fetcher = Fetcher(a.fixtures, a.save_fixtures, os.environ.get("GITHUB_TOKEN"))
    code, report, new_state = watch(state, fetcher, only)
    text = json.dumps(report, indent=1, sort_keys=True) + "\n"
    if a.report:
        a.report.write_text(text)
    if a.write_state:
        a.write_state.write_text(json.dumps(new_state, indent=1, sort_keys=True) + "\n")
    summary = {"verdict": report["verdict"], "changed": report["changed"], "errors": report["errors"],
               "unchanged": report["unchanged"]}
    print(json.dumps(summary, indent=1))
    return code


if __name__ == "__main__":
    sys.exit(main())
