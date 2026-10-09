# Releasing

One maintainer, best effort. Every push is a normal fast-forward: no `--force`, `--mirror`, `--tags` or
deletion refspec. Rulesets block force-pushes and deletions on `1.1.1*-carry`, `OpenSSL_1_1_1-continued`
and `tools`, and any move or deletion of `carry/*` and `tarball/*` tags; `1.1.1*-carry` and `tools`
require signed commits.

## The weekly watcher

`upstream-watch.yml` (on the default branch) runs `tools/watch.py` every Monday and on demand.

- **Green:** nothing changed.
- **Red, exit 1 (a change):** read the report in the run log. Run it locally with
  `python3 -I tools/watch.py --state watch-state.json --write-state /tmp/new.json`, review
  `diff watch-state.json /tmp/new.json`, act on it (below), then commit the reviewed state to `tools`
  (signed). The commit is the acknowledgement; the next run is green.
- **Red, exit 2 (a fetch error):** a source was unreachable or its format changed. Re-run; if it
  persists, fix the parser.
- The first committed `watch-state.json` (9 Oct 2026) already expects the signed `carry/1.1.1zi-jz2` tag
  (peeled `d952ab0f`), so the first run after the release push is green. The `1.1.1*-carry`, `ci` and
  `tools` heads move with ordinary pushes and are reported, not compared; every tag and
  `OpenSSL_1_1_1-continued` are compared.
- GitHub disables a scheduled workflow after 60 days without repository activity. Re-enable it in the
  Actions tab; meanwhile run the same script by hand.

| Change | Action |
|---|---|
| `al2`: a new `openssl11` version (1.1.1zj or later) | A new release: the next section. |
| `al2`: a rebuild of a known version | Download and compare its tarball sha256 with `releases.json`; a different tarball needs a note. |
| `secadv` / `vulns111` | Read the advisory. If it affects 1.1.1, decide: wait for the AL2 source, or backport from OpenSSL's public 3.x commit (labelled "unreviewed 1.1.1 backport", with a test). |
| `cpanel` | Compare their new patches with ours (`tools/ports_audit.py`); a semantic difference is a review item. |
| `kzalewski` | Informational. |
| `fork` | Expected after our own pushes: update the state with the push. Unexpected: investigate first. |

## A new OpenSSL 1.1.1 release (for example 1.1.1zj in Amazon Linux 2)

1. Resolve `mirror.list`, read `repodata/repomd.xml` and `primary.xml.gz`, and take the new SRPM's sha256
   (its pkgid) and blobstore location. Download it from
   `https://cdn.amazonlinux.com/blobstore/<sha256>/<name>`.
2. `tools/import_release.py rpm-verify SRPM --key keys/amazon-linux-2-….asc --expect-sha256 …`, then
   `rpm-extract` the tarball. Add both hashes to `releases.json`.
3. Check that it is OpenSSL's release: CHANGES has the new section, `opensslv.h` the new version, the
   member owner is root/root (a repack is noted), and the diff against the previous release matches the
   new CHANGES entries and advisories.
4. Import it (add the version to `tools/build_mirror.py` and its pins), twice into empty repositories;
   the ids must agree. Push the new import commit to `OpenSSL_1_1_1-continued` and its `tarball/1.1.1zX`
   tag (signed tag from this release on). The six upstream workflows are disabled in the repository
   settings, so the push starts nothing.
5. Reconcile the carry: diff 1.1.1zi plus the carried fixes against the new tarball, limited to the
   files the fixes touch. For each fix: keep OpenSSL's code where it differs, drop our backport once
   OpenSSL's release contains the fix, and record the comparison (a semantic difference from our port is
   worth a note to openssl-security@openssl.org). Never write "fixed in 1.1.1zX" for our own backports.
6. Create `1.1.1zX-carry` from the new import: the remaining fixes (signed, `cherry-pick -x -S`), the
   version commit `OPENSSL_VERSION_TEXT "OpenSSL 1.1.1zX-jz1  <date>"` (made when it will be published,
   never dated ahead), then cherry-pick the `.github` commits from the current carry branch: README,
   SECURITY.md, carry-ci, the watcher, and the removal of the six upstream workflows. Rulesets and CI use
   `1.1.1*-carry`, so they apply unchanged.
7. CI green on `ci` (push the new branch there first). Native and ARM `make test`, abidiff and the
   export tables against the previous carry.
8. Sign and push the tag (`git tag -s carry/1.1.1zX-jz1 <version commit>`), build the release asset with
   `git archive --format=tar --prefix=openssl-1.1.1zX-jz1/ <tag> | gzip -n -9`, write SHA256SUMS, sign it
   (`ssh-keygen -Y sign -n file`), create a draft release, check it, publish it. Add the tag and the asset
   hash to `releases.json`.
9. Switch the default branch to `1.1.1zX-carry` (Settings → General). Update the README's ref table.

## Signing

- SSH signing key `~/.ssh/id_ed25519_sign`, added to GitHub as a Signing key, offline backup. Its public
  key is in `keys/allowed_signers` with `namespaces="git,file"`.
- `git config gpg.format ssh`, `user.signingkey`, `commit.gpgSign true`, `tag.gpgSign true`.
- Release tags are signed annotated tags. The tag message repeats the base release, the carried fixes and
  the asset's sha256.
- The jz2 version commit `d952ab0f` stays unsigned: it is the hardware-tested object, and re-making it
  would change its id and the asset hash. The signed tag covers it.
- A rotated or compromised key: remove it on GitHub, publish the revocation and the new key in
  `keys/allowed_signers`, and re-sign the current release tags under new names only if needed (tags never
  move).
