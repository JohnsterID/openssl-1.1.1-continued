# tools: verification and maintenance tooling for openssl-1.1.1-continued (unofficial)

This orphan branch holds no OpenSSL code. It holds the tools and pinned inputs that let anyone re-check
[JohnsterID/openssl-1.1.1-continued](https://github.com/JohnsterID/openssl-1.1.1-continued) from public
sources, and the weekly watcher. **Not affiliated with, endorsed by, or supported by the OpenSSL Project
or the OpenSSL Corporation.** "OpenSSL" is their trademark.

| Path | What it is |
|---|---|
| `releases.json` | Every pinned input: Amazon Linux 2 `openssl11` source RPMs and their tarballs (sha256), 1.1.1w, OpenSSL's public-by-SHA commits, the fork's expected ref ids, the carry releases and the release asset hashes. |
| `keys/` | Amazon Linux 2's RPM signing key, the key that signed 1.1.1w, and (from the first signed release) `allowed_signers` with the maintainer's SSH signing key. |
| `tools/import_release.py` | Verifies a source RPM without rpm(8) (header digests, RSA and PGP signatures with gpg in a throwaway keyring), extracts the tarball, imports releases as deterministic commits, and tree-checks a commit against a tarball. |
| `tools/build_mirror.py` | Re-imports every release into an empty repository (`--result`) and compares the commit ids with the published refs (`--compare`). |
| `tools/watch.py` | The weekly watcher (run by `upstream-watch.yml` on the default branch): Amazon Linux 2 `openssl11`, OpenSSL's advisories and 1.1.1 vulnerability list, the cPanel/CloudLinux backports, kzalewski/openssl-1.1.1 and the fork's refs. |
| `watch-state.json` | The last reviewed watcher state. A watcher run stays red until a reviewed state is committed. |
| `tools/provenance.sh` | `--light`: published refs, OpenSSL's public-by-SHA commits and the pinned RPM URLs. `--full`: also downloads and verifies every input, tree-checks every `tarball/*` tag, re-imports from scratch and re-archives the carry release. |
| `tools/ports_audit.py`, `audit/` | The three-way audit of the carried backports (ours, cPanel/CloudLinux 1.1.1w, Ubuntu 3.0.2, OpenSSL 3.4): every hunk identical, cosmetic, or semantic with a reviewed explanation. |
| `RELEASING.md` | How a release is made, signed and checked, including a move to a new base (`1.1.1zj-carry`). |
| `tests/` | Unit tests for the tools (`python3 -m unittest discover -s tests`). |

## Check it yourself

```
git clone https://github.com/JohnsterID/openssl-1.1.1-continued.git && cd openssl-1.1.1-continued
git worktree add ../tools tools && cd ../tools
python3 -m unittest discover -s tests
tools/provenance.sh --light
tools/provenance.sh --full        # downloads about 75 MB; takes a few minutes
git -C ../openssl-1.1.1-continued tag -v carry/1.1.1zi-jz2   # with gpg.ssh.allowedSignersFile=keys/allowed_signers
```

What the checks prove: the import trees are exactly the content of tarballs taken from source RPMs signed
by Amazon's key (`99E6 17FE 5DB5 27C0 D8BD 5F8E 11CF 1F95 C87F 5B1A`), and a re-import gives the
published commit ids. What they don't prove: OpenSSL signs none of these tarballs, Amazon's key was
fetched from a public keyserver (not independently anchored), 1.1.1za and 1.1.1zf are Amazon repacks
(same content, other bytes), and the key that signed 1.1.1w was revoked in 2024 in a key rotation.

## Licence

OpenSSL's code on the release branches stays under OpenSSL's own licence. The tools here carry no
separate licence statement.
