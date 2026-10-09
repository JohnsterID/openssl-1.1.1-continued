# Ports audit: 1.1.1zi carry fixes 3-6

Each hunk of our 1.1.1 port is compared with the cPanel/CloudLinux `ea-openssl11` patch (1.1.1w), Ubuntu's jammy 3.0.2 port and OpenSSL's 3.4 commit. **identical**: the same changed lines; **cosmetic**: equal after removing comments and wrapping (`c/w`) or after also normalising API names (`api`: the `ossl_` prefix, `ERR_raise(ERR_LIB_X, R)` against `Xerr(X_F_..., R)`); **semantic**: anything else, each with a reviewed explanation; **absent**: the reference does not change that file. Test files are listed separately.

**Verdict: no unexplained semantic difference.**

| Reference | identical | cosmetic | semantic | absent |
|---|---|---|---|---|
| cpanel | 9 | 8 | 0 | 0 |
| ubuntu-3.0.2 | 9 | 6 | 2 | 0 |
| upstream-3.4 | 9 | 4 | 2 | 2 |

## 0003: CVE-2026-54872

Ours: `0003-ec-make-ossl_ec_scalar_mul_ladder-scalar-padding-con.patch` (sha256 `d68838e75e67f5d2…`). References: cpanel: `openssl-1.1.1w-cve-2026-54872.patch`; ubuntu-3.0.2: `CVE-2026-54872-pre1.patch`, `CVE-2026-54872.patch`; upstream-3.4: `7d83bc776499.patch`, `upstream-aaa1bda718-constant_time.patch`

| Hunk | File | -/+ | cpanel | ubuntu-3.0.2 | upstream-3.4 |
|---|---|---|---|---|---|
| 0003#0 | `crypto/bn/bn_intern.c` | 0/1 | identical | identical | identical |
| 0003#1 | `crypto/bn/bn_intern.c` | 0/36 | cosmetic (c/w) | **semantic**, explained | **semantic**, explained |
| 0003#2 | `crypto/ec/ec_mult.c` | 0/12 | cosmetic (c/w) | identical | identical |
| 0003#3 | `crypto/ec/ec_mult.c` | 0/26 | cosmetic (c/w) | cosmetic (api) | cosmetic (api) |
| 0003#4 | `include/crypto/bn.h` | 0/1 | identical | identical | identical |
| 0003#5 | `include/internal/constant_time.h` | 0/11 | identical | identical | identical |

- `0003#1:crypto/bn/bn_intern.c` vs ubuntu-3.0.2: Error queue only. Ubuntu and 3.4 push ERR_raise(ERR_LIB_BN, ERR_R_BN_LIB) when bn_wexpand() fails; ours (like cPanel's, which matches ours) returns 0 without it, because 1.1.1 has no ERR_raise and bn_wexpand() -> bn_expand2() -> bn_expand_internal() already pushes BNerr(BN_F_BN_EXPAND_INTERNAL, ...) for every failure. Same return value and control flow; the function body is otherwise token-identical.
- `0003#1:crypto/bn/bn_intern.c` vs upstream-3.4: Error queue only, as for Ubuntu: 3.4's extra ERR_raise(ERR_LIB_BN, ERR_R_BN_LIB) after a failed bn_wexpand() is dropped because 1.1.1's bn_expand_internal() already pushes a BN error; same return value and control flow.

- reference-only hunk `0003:cpanel#5:include/internal/constant_time.h` (0/13 lines): Placement only: cPanel (like Ubuntu) adds value_barrier_bn() in its own #ifdef BN_ULONG ... #endif block after constant_time_lt_64(); ours adds the identical function inside 1.1.1zi's existing #ifdef BN_ULONG block, as upstream aaa1bda718 does. Same function body, same guard.
- reference-only hunk `0003:ubuntu-3.0.2#0:include/internal/constant_time.h` (0/13 lines): Placement only, as for cPanel: the same value_barrier_bn() in a separate #ifdef BN_ULONG block; ours sits in the existing block, as upstream aaa1bda718 does.
- reference-only hunk `0003:ubuntu-3.0.2#2:crypto/bn/bn_intern.c` (0/37 lines): The reverse view of 0003#1: Ubuntu's bn_set_top_fixed() has the extra ERR_raise(ERR_LIB_BN, ERR_R_BN_LIB) that 1.1.1 lacks; bn_expand_internal() already pushes a BN error. Same return value and control flow.
- reference-only hunk `0003:upstream-3.4#1:crypto/bn/bn_intern.c` (0/37 lines): The reverse view of 0003#1: 3.4's extra ERR_raise(ERR_LIB_BN, ERR_R_BN_LIB); 1.1.1's bn_expand_internal() already pushes a BN error.
- reference-only hunk `0003:upstream-3.4#6:include/internal/constant_time.h` (0/7 lines): Not needed: constant_time_select_bn() comes with aaa1bda718 (the bn_gcd change that introduced value_barrier_bn()) and is used by none of the 54872/77696 commits (7d83bc7764, 419f5cb519), nor by cPanel's or Ubuntu's ports. The port takes only value_barrier_bn().

## 0004: CVE-2026-77696

Ours: `0004-sm2-make-sm2_sig_gen-constant-time.patch` (sha256 `dff11e15dc632457…`). References: cpanel: `openssl-1.1.1w-cve-2026-77696.patch`; ubuntu-3.0.2: `CVE-2026-77696.patch`; upstream-3.4: `419f5cb51972.patch`

| Hunk | File | -/+ | cpanel | ubuntu-3.0.2 | upstream-3.4 |
|---|---|---|---|---|---|
| 0004#0 | `crypto/ec/ec_mult.c` | 4/3 | cosmetic (c/w) | identical | identical |
| 0004#1 | `crypto/sm2/sm2_sign.c` | 0/1 | identical | identical | identical |
| 0004#2 | `crypto/sm2/sm2_sign.c` | 1/5 | identical | cosmetic (api) | cosmetic (api) |
| 0004#3 | `crypto/sm2/sm2_sign.c` | 1/0 | identical | identical | identical |
| 0004#4 | `crypto/sm2/sm2_sign.c` | 0/12 | cosmetic (c/w) | cosmetic (api) | cosmetic (api) |
| 0004#5 | `crypto/sm2/sm2_sign.c` | 7/32 | cosmetic (c/w) | cosmetic (api) | cosmetic (api) |

## 0005: CVE-2026-75806

Ours: `0005-TLS-Reject-undersized-TLS-1.2-AEAD-records-before-AE.patch` (sha256 `72f6f7ba4030925b…`). References: cpanel: `openssl-1.1.1w-cve-2026-75806.patch`; ubuntu-3.0.2: `CVE-2026-75806.patch`; upstream-3.4: `5af82fefbaf2.patch`

| Hunk | File | -/+ | cpanel | ubuntu-3.0.2 | upstream-3.4 |
|---|---|---|---|---|---|
| 0005#0 | `ssl/record/record.h` | 0/4 | cosmetic (c/w) | cosmetic (c/w) | absent, explained |
| 0005#1 | `ssl/record/ssl3_record.c` | 0/9 | cosmetic (c/w) | cosmetic (c/w) | **semantic**, explained |
| 0005#2 | `ssl/t1_enc.c` | 0/51 | identical | **semantic**, explained | absent, explained |

- `0005#0:ssl/record/record.h` vs upstream-3.4: Structural: 3.4's record layer (OSSL_RECORD_LAYER, ssl/record/methods/recmethod_local.h) already has eivlen and taglen, set in tls1_meth.c and tls_common.c, so 3.4 adds no fields. 1.1.1's RECORD_LAYER has neither; the port adds them exactly as Ubuntu's 3.0.2 port (same 1.1.1-style record layer) and cPanel's 1.1.1w port do (both cosmetic matches).
- `0005#1:ssl/record/ssl3_record.c` vs upstream-3.4: Same check, different object: 3.4 tests `!sending && reclen[ctr] < rl->eivlen + rl->taglen` in tls1_cipher() on its record-layer object rl; ours tests the same condition on s->rlayer in 1.1.1's tls1_enc(), at the same point (before EVP_CTRL_AEAD_TLS1_AAD) and returning 0 the same way. Ubuntu 3.0.2 and cPanel 1.1.1w match ours.
- `0005#2:ssl/t1_enc.c` vs ubuntu-3.0.2: API equivalents only: 3.0's s->s3 is an embedded struct (s->s3.tmp), 1.1.1's a pointer (s->s3->tmp); 3.0 tests EVP_CIPHER_is_a(c, "CHACHA20-POLY1305"), 1.1.1 has no EVP_CIPHER_is_a and tests EVP_CIPHER_nid(c) == NID_chacha20_poly1305, the same cipher. The get_mode/get_iv_length renames are normalised as API names. cPanel's 1.1.1w hunk is identical to ours.
- `0005#2:ssl/t1_enc.c` vs upstream-3.4: Absent by structure: in 3.4 the record layer computes eivlen (tls1_meth.c) and taglen (tls_common.c) when its cipher state is set, so 5af82fefba has no t1_enc.c change. In 1.1.1 tls1_change_cipher_state() is where the read cipher is set up, so the port computes both there, for the read direction only, as Ubuntu's 3.0.2 port does (API-equivalent) and cPanel's does (identical).

- reference-only hunk `0005:ubuntu-3.0.2#2:ssl/t1_enc.c` (0/50 lines): The reverse view of 0005#2: s->s3.tmp vs s->s3->tmp and EVP_CIPHER_is_a(c, "CHACHA20-POLY1305") vs EVP_CIPHER_nid(c) == NID_chacha20_poly1305, API equivalents in 1.1.1.
- reference-only hunk `0005:upstream-3.4#0:ssl/record/methods/tls1_meth.c` (0/8 lines): The reverse view of 0005#1: 3.4's check `!sending && reclen[ctr] < rl->eivlen + rl->taglen` in tls1_cipher() is ours on s->rlayer in tls1_enc(), at the same point and with the same return.

Tests: `test/recordlentest.c` +217 lines (also in: cpanel, ubuntu-3.0.2, upstream-3.4)

## 0006: CVE-2026-84782

Ours: `0006-dtls-reset-init_off-before-retransmitting-a-message.patch` (sha256 `0cd47818d8793d86…`). References: cpanel: `openssl-1.1.1w-cve-2026-84782.patch`; ubuntu-3.0.2: `CVE-2026-84782.patch`; upstream-3.4: `9f6b34422af7.patch`

| Hunk | File | -/+ | cpanel | ubuntu-3.0.2 | upstream-3.4 |
|---|---|---|---|---|---|
| 0006#0 | `ssl/d1_lib.c` | 0/17 | identical | identical | identical |
| 0006#1 | `ssl/statem/statem_dtls.c` | 0/2 | identical | identical | identical |

Tests: `test/dtlstest.c` +442 lines (also in: cpanel, ubuntu-3.0.2, upstream-3.4)

