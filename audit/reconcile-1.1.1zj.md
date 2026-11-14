# Reconciliation with OpenSSL 1.1.1zj (13 Nov 2026)

RELEASING.md "A new OpenSSL 1.1.1 release", steps 1–5, for the Amazon Linux 2 source RPM that the watcher first
reported on 19 Oct 2026.

## Source

- `openssl11-1.1.1zj-1.amzn2.0.1.src.rpm`, sha256 `0139fc06d61a96527f39d0f7be789a2466ed1f6ad029917df4281ca1bf3ce2b1`
  (its pkgid in `primary.xml.gz`, whose sha256 `6a634464…` `repomd.xml` revision 1794442927 lists). `rpm-verify`: RSA
  header and PGP header+payload signatures valid, key `99E617FE5DB527C0D8BD5F8E11CF1F95C87F5B1A`; build time
  2026-10-05T21:11:59Z.
- `openssl-1.1.1zj.tar.gz` from it: sha256 `320a3fdd38f2ef1dbef418c1255b285f6b99dc70535bc54734a8a84bd44d422b`,
  3,286 members, all `root/root` (not a repack). `opensslv.h`: `OpenSSL 1.1.1zj  29 Sep 2026`, 0x1010123fL.
- Against 1.1.1zi the tarball changes 22 files: `CHANGES`, `NEWS`, `README`, `opensslv.h`, the code of the five
  CVEs in CHANGES' new section (CVE-2026-84782, -35189, -54872, -75806, -77696) and their tests (`dtlstest`,
  `recordlentest`, `ssltestlib`, `test/build.info`). Nothing else.

## Import

`tools/build_mirror.py` with the zj pins, twice into empty repositories: the same ids. `tarball/1.1.1zj` =
`5971c6122c4a02abea86e2581dfa67e57321c281` (parent `tarball/1.1.1zi` `fb26261e`). `--compare` against the
published refs: every published `tarball/*` tag equals the re-import and `carry/1.1.1zi-jz1` rebuilds to the
published `b87631da`; the only difference is `OpenSSL_1_1_1-continued`, which the import moves one commit ahead
of the published `fb26261e` (equal once step 4 pushes it). Its message names the SRPMS snapshot that listed
the pinned SRPM when it was imported (`b74e59fb…`, 13 Nov), not the 30 Sep one of the za–zi imports: zj was
built on 5 Oct.

## The carried fixes against 1.1.1zj

Compared in the files the fixes touch (`carry/1.1.1zi-jz3` against the 1.1.1zj tarball):

| # | Fix | In 1.1.1zj | Kept on `1.1.1zj-carry` |
|---|---|---|---|
| 1 | CVE-2025-69419, alternate fix (`4191043c36`) | no: `p12_utl.c` is unchanged from 1.1.1zi | yes |
| 2 | CVE-2026-35189 | yes. Same approach and helper names (`crldp_full_name`, `ossl_dist_point_name_full`); `DIST_POINT_set_dpname()` also frees a previously set name, which our port leaked on a second call by an outside caller | no: OpenSSL's code |
| 3 | CVE-2026-54872 | yes. Same code; `value_barrier_bn()` is under `#ifdef BN_BYTES` further down `constant_time.h` | no |
| 4 | CVE-2026-77696 | yes. Same code; comments differ | no |
| 5 | CVE-2026-75806 | yes, implemented differently: `tls1_enc()` computes the minimum record length from the cipher mode and suite (GCM and CCM: an 8-byte explicit IV and a 16-byte tag; CCM8: 8 + 8; ChaCha20-Poly1305: a 16-byte tag) and keeps the old behaviour for any other AEAD. Our port stored `eivlen`/`taglen` in `RECORD_LAYER` at key change. The same records are refused for every AEAD suite 1.1.1 supports | no |
| 6 | CVE-2026-84782 | yes. Same code | no |
| 7 | musl `AT_HWCAP` (fork-specific) | no: `armcap.c` is unchanged from 1.1.1zi | yes |

No difference is a flaw in OpenSSL's code, so there is nothing to report to openssl-security@openssl.org. The
fix-2 cases of our regression tests (`test_internal_carry`) pass on OpenSSL's own 1.1.1zj; the fix-1 cases fail
there, as on 1.1.1zi, and pass with change 1.

## New since the jz3 release

- secadv/20261110 lists CVE-2026-107496 (Low) for 1.1.1; OpenSSL's 1.1.1 fix will be in 1.1.1zk (scheduled
  for 1 Dec 2026, for premium support customers only), whose source is not public. `1.1.1zj-carry` carries a 1.1.1 backport of the 4.0 commit `a8531368dd` (Jakub Zelenka; 3.5
  `a0051cfe69`, master `a957a4bfc0`) as fix 8, labelled "unreviewed 1.1.1 backport", with the upstream `ectest` case. Without the fix
  that case hangs (timeout after 20 s); with it, it passes.
- cPanel's `ea-openssl11` has a new head commit (`575c26e2`, 2 Nov: "ENG-212: Request the bot review through the bot-review kit workflow"), a workflow change, not a new patch.
- The CVE-2026-7383 follow-up `aace9bcf2e` is still missing: 1.1.1zj changes no file under `crypto/asn1/`.
