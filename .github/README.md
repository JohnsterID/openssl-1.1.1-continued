# OpenSSL 1.1.1 continued — unofficial

**Not affiliated with, endorsed by, or supported by the OpenSSL Project or the OpenSSL
Corporation.** "OpenSSL" is their trademark. This repository only republishes their source, plus two
clearly marked fixes, so that the post-1.1.1w 1.1.1 releases can be built, verified and reviewed in git.

OpenSSL 1.1.1 reached end of public support with **1.1.1w** (September 2023). OpenSSL has since issued
further 1.1.1 releases (1.1.1x onward) to its support customers. They aren't published on openssl.org
or in OpenSSL's public git. The source of several of them is publicly redistributed in Amazon Linux 2's
`openssl11` source RPMs, which is where these trees come from.

**If you can, use a supported OpenSSL (3.x).** This exists for systems that are ABI-locked to 1.1.1.

## Branches and tags

| Ref | What it is |
|---|---|
| `OpenSSL_1_1_1-continued` | OpenSSL's public `OpenSSL_1_1_1-stable` history. Then OpenSSL's own commits after 1.1.1w that are reachable by SHA in `openssl/openssl`, kept unchanged with their original authors and ids (1.1.1x, 1.1.1y and the first 1.1.1za fix). Then one commit per release: 1.1.1za, zb, zd, zf, zg, zh, zi. |
| `tarball/1.1.1zX` | The release commits on `OpenSSL_1_1_1-continued`. `git archive tarball/1.1.1zX` equals that release's tarball content, file for file. |
| `1.1.1zi-carry` (default branch) | 1.1.1zi plus the six carried fixes below, plus a distinct version text. |
| `carry/1.1.1zi-jz1` | The tagged carry release. |

1.1.1x, 1.1.1y, 1.1.1zc and 1.1.1ze have no public tarball. Their changes are contained in the next
available release commit.

## Carried fixes (on `1.1.1zi-carry` only)

1. **CVE-2025-69419, the alternate fix.** A cherry-pick of upstream `4191043c36` (Bernd Edlinger), keeping
   its original author. OpenSSL's 1.1.1ze–1.1.1zi contain only the first fix, so `OPENSSL_uni2utf8()`
   still returns NULL for BMP strings with characters that need three UTF-8 bytes (e.g. U+20AC).
2. **CVE-2026-35189 (relative CRL distribution-point names), a 1.1.1 port.** This is not OpenSSL's code:
   OpenSSL's 1.1.1 fix has no public source. It re-does upstream `c72ae182ca` for 1.1.1 and has not been
   reviewed by OpenSSL.
3. **CVE-2026-54872 (EC ladder scalar padding), a 1.1.1 backport** of OpenSSL's public 3.4 commit
   `7d83bc7764` (Igor Ustinov).
4. **CVE-2026-77696 (constant-time SM2 signing), a 1.1.1 backport** of OpenSSL's public 3.4 commit
   `419f5cb519` (Igor Ustinov, Viktor Dukhovni).
5. **CVE-2026-75806 (undersized TLS/DTLS 1.2 AEAD records), a 1.1.1 backport** of OpenSSL's public 3.4
   commit `5af82fefba` (Daniel Kubec, Mounir Idrassi), with its test.
6. **CVE-2026-84782 (DTLS retransmission from a stale offset), a 1.1.1 backport** of OpenSSL's public 3.4
   commit `9f6b34422a` (Ryan Hooper), with its test.

Fixes 3–6 keep their original authors and came after the `carry/1.1.1zi-jz1` tag. OpenSSL's own 1.1.1
fixes for them are not public, and these backports have not been reviewed by OpenSSL.

Drop each fix once an official 1.1.1 release with public source carries it.

## Version and ABI

The carry release reports `OpenSSL 1.1.1zi-jz1  30 Sep 2026`, so it can't be mistaken for OpenSSL's own
1.1.1zi. `OPENSSL_VERSION_NUMBER` (0x1010122fL), the SONAMEs (`libssl.so.1.1`, `libcrypto.so.1.1`) and
the symbol versions are unchanged, so it's a drop-in for 1.1.1 consumers.

## How to verify the release commits

Each release tree comes from an Amazon Linux 2 `openssl11` source RPM. Their signatures check against
Amazon's key `99E6 17FE 5DB5 27C0 D8BD 5F8E 11CF 1F95 C87F 5B1A`, which was fetched from a public keyserver
and is not independently anchored. OpenSSL publishes no signatures or checksums for these releases.
1.1.1za and 1.1.1zf are Amazon repacks: same content, different archive bytes.

| Release | Source RPM | RPM sha256 | Tarball sha256 |
|---|---|---|---|
| 1.1.1w | openssl.org `openssl-1.1.1w.tar.gz` (GPG-signed) | — | `cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8` |
| 1.1.1za | `openssl11-1.1.1za-1.amzn2.0.1.src.rpm` | `c63113952dd1fddf2b56fe297c721fda92bb35859ff1a2715da56fa26bbb93cb` | `d3a4439692dc9c9a828252b10dd85502b5b9bc9ab1ead54721e0bd1f6a72c074` |
| 1.1.1zb | `openssl11-1.1.1zb-1.amzn2.0.1.src.rpm` | `3b3619602474b10371e0355930c769bb048767966febeda0080e9839b3913180` | `f17cf13df642e45809fd9b635fed5cde9e0b95f64b1a0d0d4874b8208cb661ff` |
| 1.1.1zd | `openssl11-1.1.1zd-1.amzn2.0.1.src.rpm` | `cd2747ed6a640eb6668c5b99f029de97b347b97520e9be72b4e1f6ae90e92056` | `c1d619a8c61306d373b5f5b50a1939c8238f7c8e38cd6b45596308f23194945d` |
| 1.1.1zf | `openssl11-1.1.1zf-1.amzn2.0.1.src.rpm` | `49c4e7ee406c755789799665d0e87aabb9c275806ec694139b65a03137e30879` | `8bd7a2e78d2404485c4a6e9db78ccdcbd552c30663b43000763a898624f58bf9` |
| 1.1.1zg | `openssl11-1.1.1zg-1.amzn2.0.1.src.rpm` | `b565c944c4d9e25c251b24ff287ab558b22d30d39acbb28d4204cd27c2b944a6` | `8823d2c45550819e1618f704a384cf79698cbffb3884e2760935bdffbc3b2270` |
| 1.1.1zh | `openssl11-1.1.1zh-1.amzn2.0.1.src.rpm` | `75a308ebd087c03400ca0885741d4f278a980d17f7e515582a5966499e1161be` | `89ade77ad61cb264ad5f2a67caf18b291cb4fce22f608c834a6b0e091c599fc2` |
| 1.1.1zi | `openssl11-1.1.1zi-1.amzn2.0.1.src.rpm` | `5790d70cd5f66704ec6acb14119610cc3d522255f7700e16ad7d3d721f543fef` | `64f0f77354f10a8e5012e44887a7af82581a57378cfc446fc0da1fa74c1dae5a` |

To check a release, extract the tarball from the RPM, then run
`git archive --format=tar tarball/1.1.1zX | tar -t` and compare the file contents with the tarball.

This file lives in `.github/`, which OpenSSL's `.gitattributes` export-ignores, so it doesn't change any
`git archive` output or build.

## Licence

OpenSSL 1.1.1 is under the dual OpenSSL and SSLeay licence (`LICENSE`). Its notices, including the
advertising clause, are kept unchanged.

## Security

- Report issues in OpenSSL's own code to the OpenSSL Project (`openssl-security@openssl.org`).
- Report issues in the carried fixes as an issue here.
- There is no security support, embargo access or response-time commitment.
