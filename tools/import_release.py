#!/usr/bin/env python3
"""Verify Amazon Linux 2 openssl11 source RPMs and import OpenSSL's 1.1.1 release tarballs into git (B08).

Offline tooling for the OpenSSL 1.1.1 mirror-project test (docs/research/openssl-111-mirror-project.md).
Nothing here contacts a router, creates a remote repository or pushes.

Subcommands:

  rpm-verify SRPM [--key KEY.asc] [--expect-sha256 HEX]
        parse the RPM lead and headers without rpm(8); check the header SHA-256 digest, the payload digest
        and (with --key) the RSA header signature and the PGP header+payload signature with gpg in a
        throwaway keyring; print the result as JSON
  rpm-extract SRPM NAME OUT
        extract one file (e.g. openssl-1.1.1zi.tar.gz) from the SRPM's cpio payload
  import REPO MANIFEST.json
        build a deterministic release history: one commit per release in the manifest, whose tree is
        exactly the release tarball's content. Commit dates come from the tarball (newest member mtime),
        so rerunning the import yields identical commit ids. The first commit may name an upstream parent
        (the OpenSSL_1_1_1w tag commit) to graft onto upstream history.
  tree-check REPO REV TARBALL
        confirm that git tree REV equals the tarball content (paths, file modes, blob ids)
  archive REPO REV PREFIX OUT [--mtime EPOCH]
        write a gzip tarball of REV (export-ignore applied) with every member at one mtime (default: the commit's committer time),
        so the lab recipe's SOURCE_DATE_EPOCH (newest member mtime) is fixed by the commit
"""
import argparse
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile

HEADER_MAGIC = b"\x8e\xad\xe8\x01\x00\x00\x00\x00"
LEAD_SIZE = 96
# Signature-header tags (rpm lib/rpmtag.h)
SIG_RSA = 268        # OpenPGP signature over the main header
SIG_SHA1 = 269
SIG_SHA256 = 273     # hex SHA-256 of the main header
SIG_PGP = 1002       # OpenPGP signature over main header + payload
SIG_MD5 = 1004
# Main-header tags
TAG_NAME, TAG_VERSION, TAG_RELEASE = 1000, 1001, 1002
TAG_BUILDTIME = 1006
TAG_SOURCE = 1018
TAG_PAYLOADCOMPRESSOR = 1125
TAG_PAYLOADDIGEST = 5092
TAG_PAYLOADDIGESTALGO = 5093
PGPHASHALGO_SHA256 = 8


class RpmError(ValueError):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_header(data, offset):
    """Parse one RPM header structure at offset; return (entries, raw bytes, end offset)."""
    if data[offset:offset + 8] != HEADER_MAGIC:
        raise RpmError(f"no header magic at {offset}")
    nindex, hsize = struct.unpack(">II", data[offset + 8:offset + 16])
    if nindex > 100000 or hsize > 64 << 20:
        raise RpmError("implausible header size")
    index_start = offset + 16
    store = index_start + 16 * nindex
    end = store + hsize
    if end > len(data):
        raise RpmError("truncated header")
    entries = {}
    for i in range(nindex):
        tag, typ, off, count = struct.unpack(">IIII", data[index_start + 16 * i:index_start + 16 * i + 16])
        entries[tag] = (typ, off, count)
    return entries, data[offset:end], store, end


def header_value(data, store, entry):
    typ, off, count = entry
    base = store + off
    if typ == 7:  # BIN
        return data[base:base + count]
    if typ in (6, 8, 9):  # STRING, STRING_ARRAY, I18NSTRING
        out, pos = [], base
        for _ in range(count if typ != 6 else 1):
            nul = data.index(b"\x00", pos)
            out.append(data[pos:nul].decode("utf-8", "replace"))
            pos = nul + 1
        return out[0] if typ == 6 else out
    if typ == 4:  # INT32
        return list(struct.unpack(f">{count}I", data[base:base + 4 * count]))
    return None


def parse_rpm(data):
    if data[:4] != b"\xed\xab\xee\xdb":
        raise RpmError("not an RPM (lead magic)")
    sig_entries, _, sig_store, sig_end = parse_header(data, LEAD_SIZE)
    main_off = sig_end + (-sig_end % 8)
    main_entries, main_raw, main_store, main_end = parse_header(data, main_off)
    sig = {tag: header_value(data, sig_store, e) for tag, e in sig_entries.items()}
    main = {tag: header_value(data, main_store, e) for tag, e in main_entries.items()
            if tag in (TAG_NAME, TAG_VERSION, TAG_RELEASE, TAG_BUILDTIME, TAG_SOURCE, TAG_PAYLOADCOMPRESSOR,
                       TAG_PAYLOADDIGEST, TAG_PAYLOADDIGESTALGO)}
    return {"sig": sig, "main": main, "header": main_raw, "payload": data[main_end:], "main_offset": main_off}


def gpg_verify(sig_bytes, signed_bytes, key_path):
    """Verify a detached OpenPGP signature with a throwaway keyring; return the VALIDSIG fingerprint."""
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        env = dict(os.environ, GNUPGHOME=home)
        subprocess.run(["gpg", "--batch", "--quiet", "--import", str(key_path)], env=env, check=True,
                       capture_output=True)
        sig_file, data_file = Path(home, "s.sig"), Path(home, "d.bin")
        sig_file.write_bytes(sig_bytes)
        data_file.write_bytes(signed_bytes)
        r = subprocess.run(["gpg", "--batch", "--status-fd", "1", "--verify", str(sig_file), str(data_file)],
                           env=env, capture_output=True, text=True, errors="replace")
        valid = [line.split()[2] for line in r.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
        if r.returncode != 0 or not valid:
            raise RpmError(f"signature does not verify: {r.stderr.strip()[-300:]}")
        return valid[0]


def rpm_verify(path, key=None, expect_sha256=None):
    data = Path(path).read_bytes()
    file_sha = hashlib.sha256(data).hexdigest()
    if expect_sha256 and file_sha != expect_sha256:
        raise RpmError(f"{path}: sha256 {file_sha} != expected {expect_sha256}")
    rpm = parse_rpm(data)
    # rpm 4.11 (Amazon Linux 2) writes a SHA-1 header digest only; newer rpm adds SHA-256.
    header_digests = []
    for tag, algo in ((SIG_SHA256, hashlib.sha256), (SIG_SHA1, hashlib.sha1)):
        if tag in rpm["sig"]:
            if rpm["sig"][tag] != algo(rpm["header"]).hexdigest():
                raise RpmError(f"header {algo().name} digest mismatch")
            header_digests.append(algo().name)
    if not header_digests:
        raise RpmError("RPM carries no header digest")
    md5 = hashlib.md5(rpm["header"] + rpm["payload"]).digest()
    if SIG_MD5 in rpm["sig"] and rpm["sig"][SIG_MD5] != md5:
        raise RpmError("header+payload MD5 mismatch")
    result = {"file": Path(path).name, "sha256": file_sha, "size": len(data), "header_digests_ok": header_digests,
              "md5_ok": SIG_MD5 in rpm["sig"],
              "name": rpm["main"].get(TAG_NAME), "version": rpm["main"].get(TAG_VERSION),
              "release": rpm["main"].get(TAG_RELEASE), "buildtime": (rpm["main"].get(TAG_BUILDTIME) or [None])[0],
              "payload_compressor": rpm["main"].get(TAG_PAYLOADCOMPRESSOR),
              "sources": rpm["main"].get(TAG_SOURCE)}
    digests = rpm["main"].get(TAG_PAYLOADDIGEST)
    if digests:
        algo = (rpm["main"].get(TAG_PAYLOADDIGESTALGO) or [PGPHASHALGO_SHA256])[0]
        if algo != PGPHASHALGO_SHA256:
            raise RpmError(f"unsupported payload digest algorithm {algo}")
        if hashlib.sha256(rpm["payload"]).hexdigest() != digests[0]:
            raise RpmError("payload SHA-256 digest mismatch")
        result["payload_sha256_ok"] = True
    if key:
        if SIG_RSA not in rpm["sig"] or SIG_PGP not in rpm["sig"]:
            raise RpmError("RPM carries no RSA/PGP signature")
        result["rsa_header_signer"] = gpg_verify(rpm["sig"][SIG_RSA], rpm["header"], key)
        result["pgp_header_payload_signer"] = gpg_verify(rpm["sig"][SIG_PGP], rpm["header"] + rpm["payload"], key)
    return result


def decompress(payload, compressor):
    if compressor in ("xz", "lzma"):
        return lzma.decompress(payload)
    if compressor == "gzip":
        return gzip.decompress(payload)
    raise RpmError(f"unsupported payload compressor {compressor}")


def cpio_members(archive):
    """Yield (name, bytes) from a newc cpio archive."""
    pos = 0
    while pos + 110 <= len(archive):
        hdr = archive[pos:pos + 110]
        if hdr[:6] not in (b"070701", b"070702"):
            raise RpmError(f"bad cpio magic at {pos}")
        fields = [int(hdr[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        filesize, namesize = fields[6], fields[11]
        name_start = pos + 110
        name = archive[name_start:name_start + namesize - 1].decode()
        data_start = name_start + namesize
        data_start += -data_start % 4
        if name == "TRAILER!!!":
            return
        yield name.lstrip("./"), archive[data_start:data_start + filesize]
        pos = data_start + filesize
        pos += -pos % 4


def rpm_extract(path, name, out):
    rpm = parse_rpm(Path(path).read_bytes())
    try:
        archive = decompress(rpm["payload"], rpm["main"].get(TAG_PAYLOADCOMPRESSOR))
    except (lzma.LZMAError, OSError, EOFError) as e:
        raise RpmError(f"{path}: payload does not decompress: {e}") from e
    for member, content in cpio_members(archive):
        if member == name:
            Path(out).write_bytes(content)
            return hashlib.sha256(content).hexdigest()
    raise RpmError(f"{name} not in {path}")


# ---------------------------------------------------------------------------------------------- git import

def git(repo, *args, env=None, input_bytes=None):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=env, input=input_bytes)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.decode()[-500:]}")
    return r.stdout.decode().strip()


def tarball_listing(tarball):
    """{relative path: (mode, sha1-blob-id)} for regular files and symlinks, top directory stripped."""
    out = {}
    with tarfile.open(tarball, "r:*") as tf:
        for m in tf.getmembers():
            parts = m.name.split("/", 1)
            if len(parts) < 2 or not parts[1]:
                continue
            rel = parts[1].rstrip("/")
            if m.isdir():
                continue
            if m.issym():
                data, mode = m.linkname.encode(), "120000"
            elif m.isfile():
                data = tf.extractfile(m).read()
                mode = "100755" if m.mode & 0o111 else "100644"
            else:
                raise RuntimeError(f"unsupported tar member {m.name}")
            blob = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
            out[rel] = (mode, blob)
    return out


def newest_mtime(tarball):
    with tarfile.open(tarball, "r:*") as tf:
        return max(int(m.mtime) for m in tf.getmembers() if m.isfile())


def tree_listing(repo, rev):
    out = {}
    raw = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "-z", rev], capture_output=True,
                         check=True).stdout.decode()
    for rec in raw.split("\x00"):
        if not rec:
            continue
        meta, path = rec.split("\t", 1)
        mode, _typ, blob = meta.split()
        out[path] = (mode, blob)
    return out


def archive_listing(repo, rev):
    """Like tree_listing, but of `git archive REV`, i.e. with .gitattributes export-ignore applied."""
    raw = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", "--prefix=x/", rev],
                         capture_output=True, check=True).stdout
    with tempfile.NamedTemporaryFile(suffix=".tar.gz") as tmp:
        tmp.write(gzip.compress(raw, mtime=0))
        tmp.flush()
        return tarball_listing(tmp.name)


def export_ignored(repo, rev):
    """Paths in REV's tree that `git archive REV` leaves out (export-ignore)."""
    tree = tree_listing(repo, rev)
    return {p: tree[p] for p in set(tree) - set(archive_listing(repo, rev))}


def tree_check(repo, rev, tarball, archive_mode=False):
    a = archive_listing(repo, rev) if archive_mode else tree_listing(repo, rev)
    b = tarball_listing(tarball)
    missing = sorted(set(b) - set(a))
    extra = sorted(set(a) - set(b))
    differ = sorted(p for p in set(a) & set(b) if a[p] != b[p])
    return {"rev": rev, "tarball": Path(tarball).name, "mode": "git-archive" if archive_mode else "tree",
            "files": len(b), "equal": not (missing or extra or differ),
            "missing_in_tree": missing[:20], "extra_in_tree": extra[:20], "differ": differ[:20]}


def import_releases(repo, manifest):
    """manifest: {"author": ..., "email": ..., "tz": "+0000", "parent": sha|None,
                  "releases": [{"version", "tarball", "tarball_sha256", "message"}]}"""
    repo = Path(repo)
    if not (repo / ".git").exists() and not (repo / "HEAD").exists():
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
    parent = manifest.get("parent")
    results = []
    for rel in manifest["releases"]:
        tb = rel["tarball"]
        got = sha256_file(tb)
        if got != rel["tarball_sha256"]:
            raise RuntimeError(f"{tb}: sha256 {got} != manifest {rel['tarball_sha256']}")
        with tempfile.TemporaryDirectory() as work:
            with tarfile.open(tb, "r:*") as tf:
                tf.extractall(work, filter="tar") if sys.version_info >= (3, 12) else tf.extractall(work)
            tops = os.listdir(work)
            if len(tops) != 1:
                raise RuntimeError(f"{tb}: expected one top directory, got {tops}")
            src = Path(work, tops[0])
            index = Path(work, "index")
            env = dict(os.environ, GIT_INDEX_FILE=str(index), GIT_WORK_TREE=str(src))
            kept = {}
            if manifest.get("keep_export_ignored") and parent:
                # Git-shaped history: carry the parent's export-ignored paths (fuzz corpora, .github,
                # .gitattributes, submodules), which release tarballs never contain.
                kept = export_ignored(repo, parent)
                clash = sorted(set(kept) & set(tarball_listing(tb)))
                if clash:
                    raise RuntimeError(f"{tb}: tarball contains export-ignored paths {clash[:5]}")
                info = "".join(f"{mode} {blob}\t{path}\n" for path, (mode, blob) in sorted(kept.items()))
                git(repo, "update-index", "--add", "--index-info", env=env, input_bytes=info.encode())
            gitdir = git(repo, "rev-parse", "--absolute-git-dir")
            r = subprocess.run(["git", "--git-dir", gitdir, "--work-tree", str(src), "add", "--ignore-removal", "-f",
                                "."], cwd=src, env=env, capture_output=True)
            if r.returncode:
                raise RuntimeError(f"git add: {r.stderr.decode()[-500:]}")
            tree = git(repo, "write-tree", env=env)
        when = newest_mtime(tb)
        date = f"{when} {manifest.get('tz', '+0000')}"
        cenv = dict(os.environ, GIT_AUTHOR_NAME=manifest["author"], GIT_AUTHOR_EMAIL=manifest["email"],
                    GIT_COMMITTER_NAME=manifest["author"], GIT_COMMITTER_EMAIL=manifest["email"],
                    GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
        args = ["commit-tree", "--no-gpg-sign", tree] + (["-p", parent] if parent else []) + ["-F", "-"]
        commit = git(repo, *args, env=cenv, input_bytes=rel["message"].encode())
        tag = rel.get("tag")
        if tag:
            git(repo, "tag", "--no-sign", "-f", tag, commit)  # lightweight; immune to a global tag.gpgSign
        results.append({"version": rel["version"], "commit": commit, "tree": tree, "date_epoch": when,
                        "tag": tag, "kept_export_ignored": len(kept)})
        parent = commit
    if manifest.get("branch"):
        git(repo, "update-ref", f"refs/heads/{manifest['branch']}", parent)
    return results


def archive(repo, rev, prefix, out, mtime=None):
    """Deterministic tar.gz of rev: sorted members, one mtime, uid/gid 0, gzip mtime 0."""
    if mtime is None:
        mtime = int(git(repo, "log", "-1", "--format=%ct", rev))
    listing = archive_listing(repo, rev)  # export-ignore applied, like a release tarball
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        dirs = set()
        for path in sorted(listing):
            parts = path.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                dirs.add("/".join(parts[:i]))
        entries = [(d, None) for d in dirs] + [(p, listing[p]) for p in listing]
        entries.sort(key=lambda e: e[0])
        root = tarfile.TarInfo(prefix)
        root.type, root.mode, root.mtime = tarfile.DIRTYPE, 0o755, mtime
        tf.addfile(root)
        for path, meta in entries:
            ti = tarfile.TarInfo(f"{prefix}/{path}")
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = mtime, 0, 0, "", ""
            if meta is None:
                ti.type, ti.mode = tarfile.DIRTYPE, 0o755
                tf.addfile(ti)
                continue
            mode, blob = meta
            data = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", blob], capture_output=True,
                                  check=True).stdout
            if mode == "120000":
                ti.type, ti.linkname, ti.mode = tarfile.SYMTYPE, data.decode(), 0o777
                tf.addfile(ti)
            else:
                ti.mode = 0o755 if mode == "100755" else 0o644
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    with open(out, "wb") as f, gzip.GzipFile(fileobj=f, mode="wb", mtime=0, filename="") as gz:
        gz.write(buf.getvalue())
    return sha256_file(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("rpm-verify")
    p.add_argument("srpm")
    p.add_argument("--key")
    p.add_argument("--expect-sha256")
    p = sub.add_parser("rpm-extract")
    p.add_argument("srpm")
    p.add_argument("name")
    p.add_argument("out")
    p = sub.add_parser("import")
    p.add_argument("repo")
    p.add_argument("manifest")
    p = sub.add_parser("tree-check")
    p.add_argument("repo")
    p.add_argument("rev")
    p.add_argument("tarball")
    p.add_argument("--git-archive", action="store_true", help="compare `git archive REV` (export-ignore applied)")
    p = sub.add_parser("archive")
    p.add_argument("repo")
    p.add_argument("rev")
    p.add_argument("prefix")
    p.add_argument("out")
    p.add_argument("--mtime", type=int)
    a = ap.parse_args()
    if a.cmd == "rpm-verify":
        res = rpm_verify(a.srpm, a.key, a.expect_sha256)
    elif a.cmd == "rpm-extract":
        res = {"sha256": rpm_extract(a.srpm, a.name, a.out), "out": a.out}
    elif a.cmd == "import":
        res = import_releases(a.repo, json.loads(Path(a.manifest).read_text()))
    elif a.cmd == "tree-check":
        res = tree_check(a.repo, a.rev, a.tarball, a.git_archive)
    else:
        res = {"sha256": archive(a.repo, a.rev, a.prefix, a.out, a.mtime), "out": a.out}
    json.dump(res, sys.stdout, indent=1, default=lambda b: b.hex() if isinstance(b, bytes) else str(b))
    print()
    return 0 if not isinstance(res, dict) or res.get("equal", True) else 1


if __name__ == "__main__":
    sys.exit(main())
