# OpenSSL 1.1.1 continued — unofficial

**Not affiliated with, endorsed by, or supported by the OpenSSL Project or the OpenSSL
Corporation.** "OpenSSL" is their trademark. This repository only republishes their source, plus three
clearly marked changes, so that the post-1.1.1w 1.1.1 releases can be built, verified and reviewed in git.

OpenSSL 1.1.1 reached end of public support with **1.1.1w** (September 2023). OpenSSL has since issued
further 1.1.1 releases (1.1.1x onward) to its support customers. They aren't published on openssl.org
or in OpenSSL's public git. The source of several of them is publicly redistributed in Amazon Linux 2's
`openssl11` source RPMs, which is where these trees come from.

**If you can, use a supported OpenSSL (3.x).** This exists for systems that are ABI-locked to 1.1.1.

## Branches and tags

| Ref | What it is |
|---|---|
| `OpenSSL_1_1_1-continued` | OpenSSL's public `OpenSSL_1_1_1-stable` history. Then OpenSSL's own commits after 1.1.1w that are reachable by SHA in `openssl/openssl`, kept unchanged with their original authors and ids (1.1.1x, 1.1.1y and the first 1.1.1za fix). Then one commit per release: 1.1.1za, zb, zd, zf, zg, zh, zi, zj. |
| `tarball/1.1.1zX` | The release commits on `OpenSSL_1_1_1-continued`. `git archive tarball/1.1.1zX` equals that release's tarball content, file for file. |
| `1.1.1zj-carry` (default branch) | 1.1.1zj plus the three carried changes below, plus a distinct version text. |
| `carry/1.1.1zj-jz1` | The current tagged carry release: 1.1.1zj plus carried changes 1, 7 and 8. Signed tag. |
| `1.1.1zi-carry` | The previous release branch: 1.1.1zi plus fixes 1–7. Not updated any more. |
| `carry/1.1.1zi-jz3`, `-jz2`, `-jz1` | The 1.1.1zi carry releases: fixes 1–7, 1–6, and 1–2. Move to `carry/1.1.1zj-jz1`. |
| `tools` | No OpenSSL code: the importer, the upstream watcher, pinned inputs (`releases.json`), keys, the ports audit and `RELEASING.md`. |

1.1.1x, 1.1.1y, 1.1.1zc and 1.1.1ze have no public tarball. Their changes are contained in the next
available release commit.

## Carried changes (on `1.1.1zj-carry` only)

| # | Change | Upstream source | Status | Independent comparison | Tests | Reference router build (`no-dtls no-sm2`, RSA certificates) |
|---|---|---|---|---|---|---|
| 1 | CVE-2025-69419, the alternate fix | cherry-pick of `4191043c36` (Bernd Edlinger), original author kept | OpenSSL's own code (3.0 branch); not in 1.1.1zj | — | `test_internal_carry` | reachable (BMP string and PKCS#12 friendlyName conversion) |
| 7 | Not a CVE: on musl Linux, ARM capability detection reads `AT_HWCAP` instead of SIGILL probes | **fork-specific portability fix** (`crypto/armcap.c`); no OpenSSL release has it, master included | ours | — | a static musl test program with a wrapped `getauxval()` under qemu-user (arm and aarch64); run on two BCM63138 routers | glibc builds compile to the same object; affects static musl builds only |
| 8 | CVE-2026-107496, EC key generation loops forever for a group order of 1 | backport of 4.0 `a8531368dd` (Jakub Zelenka; 3.5 `a0051cfe69`, master `a957a4bfc0`) | **unreviewed 1.1.1 backport** | — (OpenSSL's 1.1.1 fix will be in 1.1.1zk, scheduled for 1 Dec 2026 for its premium support customers only) | the upstream `ectest` case (hangs without the fix) | reachable only through `CMS_encrypt()` to a hostile EC certificate; in the stock rootfs only the `openssl` CLI imports it |

- **"Unreviewed 1.1.1 backport"** means that OpenSSL has not reviewed this code. It **will be replaced by
  OpenSSL's code when 1.1.1zk source is public**: the `tools` watcher checks Amazon Linux 2 for an
  `openssl11` 1.1.1zk source RPM every week.
- Change 8 keeps its original author. In 1.1.1 the loop is in `ec_key_simple_generate_key()`, which every
  built-in EC method uses; the error is `ECerr(EC_F_EC_KEY_GENERATE_KEY, EC_R_INVALID_GROUP_ORDER)`.
- **Change 7:** without it, a static musl build probes NEON and the ARMv8 crypto instructions under a SIGILL
  handler and trusts the result. On a kernel built without VFP/NEON support (seen on BCM63138 routers running
  Linux 4.1), the probe passed on one core and failed on the other, and a process that later ran a NEON
  routine on the other core died with SIGILL. musl has had `getauxval()` since 1.1.0. glibc, Android and BSD
  builds are unchanged.
- Drop 1 and 8 once an official 1.1.1 release with public source carries them. 7 stays until OpenSSL itself
  reads `AT_HWCAP` on musl.

### Replaced by OpenSSL's code in 1.1.1zj

The 1.1.1zi carry releases carried unreviewed 1.1.1 backports of five CVEs (fix 2 from jz1, fixes 3–6 from
jz2) that OpenSSL also fixed in its 1.1.1zj (29 Sep 2026), whose source was not public then. On
`1.1.1zj-carry` they are gone: the code is OpenSSL's. Compared with our ports,
in the files they touched:

| # | CVE | OpenSSL's 1.1.1zj compared with our port |
|---|---|---|
| 2 | CVE-2026-35189, relative CRL distribution-point names | the same approach and helper names; `DIST_POINT_set_dpname()` also frees a name set earlier (ours leaked it on a second call by an outside caller) |
| 3 | CVE-2026-54872, EC ladder scalar padding | the same code; `value_barrier_bn()` sits under `#ifdef BN_BYTES` further down `constant_time.h` |
| 4 | CVE-2026-77696, constant-time SM2 signing | the same code (comments differ) |
| 5 | CVE-2026-75806, undersized DTLS 1.2 AEAD records | the same check, implemented differently: OpenSSL computes the minimum length in `tls1_enc()` from the cipher mode and suite (GCM, CCM, CCM8, ChaCha20-Poly1305); ours stored the explicit IV and tag lengths in `RECORD_LAYER` when the keys changed. Same result for every AEAD suite 1.1.1 supports |
| 6 | CVE-2026-84782, DTLS retransmission from a stale offset | the same code |

None of the differences is a flaw in OpenSSL's code. The fix-2 cases of our regression tests
(`test_internal_carry`) pass on OpenSSL's own 1.1.1zj; the fix-1 cases need change 1.

## Version and ABI

The carry release reports `OpenSSL 1.1.1zj-jz1  14 Nov 2026` (the 1.1.1zi carry releases reported
`OpenSSL 1.1.1zi-jz3  12 Oct 2026`, `-jz2  3 Oct 2026` and `-jz1  30 Sep 2026`), so it can't be mistaken
for OpenSSL's own 1.1.1zj.
`OPENSSL_VERSION_NUMBER` is 1.1.1zj's (0x1010123fL); the SONAMEs (`libssl.so.1.1`, `libcrypto.so.1.1`) and
the symbol versions are unchanged, so it's a drop-in for 1.1.1 consumers.

## Tested

- zj-jz1 (14 Nov 2026):
  - `make test` on x86_64 (gcc 13) passes 161 recipes / 2667 tests, including `test_internal_carry`; the new
    `ectest` case hangs without change 8 and passes with it;
  - 32-bit ARM (cortex-a9, soft-float), the router's Configure options, under qemu-user with qemu's default
    CPU and with `cortex-a9`: no failure beyond the two cipher-order tests (`test_cipherlist`, `test_sslapi`)
    that the device's ChaCha20-first default changes in every 1.1.1 build;
  - the router build of `libcrypto.so.1.1` and `libssl.so.1.1` keeps every SONAME, version node and export of
    the stock 1.1.1g pair, adds the same four exports as before, changes no object size, and resolves all
    1,504 symbols that 56 stock consumers import; under qemu the stock `openssl` CLI (TLS 1.3 and 1.2
    handshakes), the 56 consumers and the stock nginx web GUI (TLS 1.0–1.2 as configured, SRP login) behave
    as on the stock pair.
- The 1.1.1zi carry releases:
  - jz1–jz3: `make test` on x86_64 passed 160 recipes / 2666 tests (161 / 2667 with `test_internal_carry`), and
    the ARM build under qemu-user failed only the same two cipher-order tests;
  - jz2 on hardware: the libraries built from `carry/1.1.1zi-jz2` with the router recipe ran on a spare DJA0231
    router (BCM63138, 3 Oct 2026): TLS 1.2/1.3 with RSA, P-384 and P-521, its web GUI (nginx), and ten
    consumers restarted one by one, with no crash or reboot;
  - jz3 (12 Oct 2026): the exported symbols and version nodes of `libcrypto.so.1.1` (4413) and `libssl.so.1.1`
    (499) equal jz2's; built for 32-bit ARM with glibc, `crypto/armcap.c` preprocesses and compiles to the same
    output as in jz2.
- Change 7, static musl (gcc 11.2, musl 1.2.3), with a test program whose `getauxval()` returns a kernel
  HWCAP without NEON/ASIMD under qemu-user:
  - before the fix, `OPENSSL_armcap_P` was 0x3d on arm and 0x7f on aarch64;
  - with it, 0x0 and 0x2 (timer only).
  - On two BCM63138 routers, the arm test binary (byte-identical when rebuilt from the jz3 tree) reported no
    NEON in any run: 0 of 20 on one; 0 of 15 pinned to each core and 0 of 20 unpinned on the other. The unfixed
    build reported NEON in 15 of 15 runs pinned to the first core and 0 of 15 on the second.
- CI (`carry-ci.yml`) builds and tests the default and the router configurations on Ubuntu 24.04 and
  22.04, an AddressSanitizer + UndefinedBehaviorSanitizer build, and the ARM build under qemu. Its runs
  are in the Actions tab.

## How to verify

- **The release tag:** `git tag -v carry/1.1.1zj-jz1`, with an `allowed_signers` file holding the key
  below (`git config gpg.ssh.allowedSignersFile allowed_signers`). The `tools` branch holds the file.
  - Signing key (SSH, ed25519): `SHA256:pNKgXGMFPyNsg5EwoECScta8iEzzAENElEkGvS/ZugU`
- **The release tarball:** the release asset `openssl-1.1.1zj-jz1.tar.gz` is
  `git archive --format=tar --prefix=openssl-1.1.1zj-jz1/ carry/1.1.1zj-jz1 | gzip -n -9`, sha256
  `57facda29610d2f4964569c34df4ab9ba5536ab9121db18aa3264ceda7c82192`; `SHA256SUMS.sig` signs its
  checksum. (`openssl-1.1.1zi-jz3.tar.gz`: `1c693f27e23a541cf649275bdffdbd0c70ae1dc6c4b215b798e9810c5c33578f`.) GitHub's automatic "Source code" archives use another prefix and aren't byte-stable.
- **The release commits:** each tree comes from an Amazon Linux 2 `openssl11` source RPM. Their
  signatures check against Amazon's key `99E6 17FE 5DB5 27C0 D8BD 5F8E 11CF 1F95 C87F 5B1A`, which Amazon
  serves at `https://cdn.amazonlinux.com/_assets/11CF1F95C87F5B1A.asc` (a public keyserver gives the same key). OpenSSL publishes no signatures or
  checksums for these releases. 1.1.1za and 1.1.1zf are Amazon repacks: same content, different archive
  bytes. The `tools` branch re-checks all of it in one command (it needs git, curl, gpg and Python 3, and
  downloads every pinned input from Amazon's blobstore and openssl.org):
  ```
  git fetch origin tools && git worktree add ../tools tools && cd ../tools
  tools/provenance.sh --full
  ```
  It checks each source RPM's signatures and checksum, compares every `tarball/*` tag with its tarball
  (`git archive`), re-imports all releases into an empty repository and compares the commit ids with the
  published `OpenSSL_1_1_1-continued` and `tarball/*`, and re-makes each carry release asset. `releases.json` pins every input:

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
| 1.1.1zj | `openssl11-1.1.1zj-1.amzn2.0.1.src.rpm` | `0139fc06d61a96527f39d0f7be789a2466ed1f6ad029917df4281ca1bf3ce2b1` | `320a3fdd38f2ef1dbef418c1255b285f6b99dc70535bc54734a8a84bd44d422b` |

This file lives in `.github/`, which OpenSSL's `.gitattributes` export-ignores, so it doesn't change any
`git archive` output or build.

## Known limits

- OpenSSL's 1.1.1zk may contain fixes that it hasn't announced; nobody outside its support customers
  can check.
- The CVE-2026-7383 follow-up `aace9bcf2e` is missing, as in OpenSSL's own 1.1.1zi and 1.1.1zj.
- No FIPS module, no support, no embargo access. One maintainer, best effort.

## Licence

OpenSSL 1.1.1 is under the dual OpenSSL and SSLeay licence (`LICENSE`). Its notices, including the
advertising clause, are kept unchanged.

## Security

See [SECURITY.md](SECURITY.md) for where to report what. There is no security support, embargo access or
response-time commitment.
