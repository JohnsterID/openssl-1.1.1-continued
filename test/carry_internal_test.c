/*
 * Copyright 2026 JohnsterID (1.1.1zi-carry). Not part of OpenSSL's own tests.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Regression tests for the fixes carried on 1.1.1zi-carry that OpenSSL's
 * own 1.1.1 test suite does not cover:
 *
 *  - CVE-2025-69419 (alternate fix, upstream 4191043c36): OPENSSL_uni2utf8()
 *    and PKCS#12 friendly names must convert BMP strings whose characters
 *    need three UTF-8 bytes, wherever such a character appears.  The
 *    upstream test only covers a lone U+2192.
 *  - CVE-2026-35189 (1.1.1 port of upstream c72ae182ca): caching a
 *    certificate's extensions must not build the full name of each
 *    nameRelativeToCRLIssuer distribution point, and CRL matching against
 *    such a distribution point must still work.
 *
 * This is an internal test because the deferred-name check looks at the
 * cached distribution points in struct x509_st.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "crypto/x509.h"
#include "testutil.h"
#include "internal/nelem.h"

/* CVE-2025-69419 */

static const struct {
    const char *label;
    const unsigned char bmp[4];
    int len;
    const char *utf8;
} uni2utf8_cases[] = {
    { "U+2192 alone", { 0x21, 0x92 }, 2, "\xe2\x86\x92" },
    { "x then U+20AC", { 0x00, 'x', 0x20, 0xac }, 4, "x\xe2\x82\xac" },
    { "U+20AC then x", { 0x20, 0xac, 0x00, 'x' }, 4, "\xe2\x82\xac" "x" },
};

static int test_uni2utf8(int idx)
{
    char *out = OPENSSL_uni2utf8(uni2utf8_cases[idx].bmp,
                                 uni2utf8_cases[idx].len);
    int ok;

    TEST_info("%s", uni2utf8_cases[idx].label);
    ok = TEST_ptr(out) && TEST_str_eq(out, uni2utf8_cases[idx].utf8);
    OPENSSL_free(out);
    return ok;
}

static const char *friendly_names[] = {
    "plain",
    "x\xe2\x82\xac",            /* x, EURO SIGN */
    "\xe2\x82\xac" "x",         /* EURO SIGN, x */
    "\xe2\x86\x92",             /* RIGHTWARDS ARROW */
};

static int test_p12_friendlyname(int idx)
{
    X509 *x = NULL;
    PKCS12_SAFEBAG *bag = NULL;
    char *got = NULL;
    int ok = 0;

    if (!TEST_ptr(x = X509_new())
        || !TEST_ptr(bag = PKCS12_SAFEBAG_create_cert(x))
        || !TEST_true(PKCS12_add_friendlyname_utf8(bag, friendly_names[idx],
                                                   -1)))
        goto err;
    got = PKCS12_get_friendlyname(bag);
    ok = TEST_ptr(got) && TEST_str_eq(got, friendly_names[idx]);
 err:
    OPENSSL_free(got);
    PKCS12_SAFEBAG_free(bag);
    X509_free(x);
    return ok;
}

/* CVE-2026-35189 */

static EVP_PKEY *make_key(void)
{
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *key = NULL;

#ifndef OPENSSL_NO_EC
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (kctx == NULL
        || EVP_PKEY_keygen_init(kctx) <= 0
        || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx,
                                                  NID_X9_62_prime256v1) <= 0
        || EVP_PKEY_keygen(kctx, &key) <= 0)
        key = NULL;
#else
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (kctx == NULL
        || EVP_PKEY_keygen_init(kctx) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0
        || EVP_PKEY_keygen(kctx, &key) <= 0)
        key = NULL;
#endif
    EVP_PKEY_CTX_free(kctx);
    return key;
}

/* A stack holding one relative distribution point name "CN=<cn>". */
static DIST_POINT_NAME *relative_dpname(const char *cn)
{
    DIST_POINT_NAME *dpn = DIST_POINT_NAME_new();
    X509_NAME_ENTRY *ne = NULL;

    if (dpn == NULL)
        return NULL;
    dpn->type = 1;
    if ((dpn->name.relativename = sk_X509_NAME_ENTRY_new_null()) == NULL
        || (ne = X509_NAME_ENTRY_create_by_txt(NULL, "CN", MBSTRING_ASC,
                                               (const unsigned char *)cn,
                                               -1)) == NULL
        || !sk_X509_NAME_ENTRY_push(dpn->name.relativename, ne)) {
        X509_NAME_ENTRY_free(ne);
        DIST_POINT_NAME_free(dpn);
        return NULL;
    }
    return dpn;
}

static int add_crldp(X509 *x, int ndp)
{
    CRL_DIST_POINTS *crldp = sk_DIST_POINT_new_null();
    char cn[32];
    int i, ok = 0;

    if (crldp == NULL)
        return 0;
    for (i = 0; i < ndp; i++) {
        DIST_POINT *dp = DIST_POINT_new();

        BIO_snprintf(cn, sizeof(cn), "dp-%d", i);
        if (dp == NULL || (dp->distpoint = relative_dpname(cn)) == NULL
            || !sk_DIST_POINT_push(crldp, dp)) {
            DIST_POINT_free(dp);
            goto err;
        }
    }
    ok = X509_add1_ext_i2d(x, NID_crl_distribution_points, crldp, 0, 0);
 err:
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    return ok;
}

/* Re-parse a certificate, so that its extension cache starts empty. */
static X509 *reparse(X509 *x)
{
    unsigned char *der = NULL;
    const unsigned char *p;
    int len = i2d_X509(x, &der);
    X509 *ret = NULL;

    if (len > 0) {
        p = der;
        ret = d2i_X509(NULL, &p, len);
    }
    OPENSSL_free(der);
    return ret;
}

static X509 *make_cert(X509_NAME *subject, X509_NAME *issuer, EVP_PKEY *pub,
                       EVP_PKEY *signer, long serial, int is_ca, int ndp)
{
    X509 *x = X509_new(), *ret = NULL;
    X509_EXTENSION *ext = NULL;

    if (x == NULL
        || !X509_set_version(x, 2)
        || !ASN1_INTEGER_set(X509_get_serialNumber(x), serial)
        || !X509_set_subject_name(x, subject)
        || !X509_set_issuer_name(x, issuer)
        || X509_gmtime_adj(X509_getm_notBefore(x), -86400L) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(x), 30 * 86400L) == NULL
        || !X509_set_pubkey(x, pub))
        goto err;
    if (is_ca) {
        if ((ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
                                       "critical,CA:TRUE")) == NULL
            || !X509_add_ext(x, ext, -1))
            goto err;
    }
    if (ndp > 0 && !add_crldp(x, ndp))
        goto err;
    if (X509_sign(x, signer, EVP_sha256()) <= 0)
        goto err;
    ret = reparse(x);
 err:
    X509_EXTENSION_free(ext);
    X509_free(x);
    return ret;
}

static X509_NAME *make_name(const char *cn, int extra_rdns)
{
    X509_NAME *nm = X509_NAME_new();
    char ou[64];
    int i;

    if (nm == NULL)
        return NULL;
    for (i = 0; i < extra_rdns; i++) {
        BIO_snprintf(ou, sizeof(ou), "unit-%03d-xxxxxxxxxxxxxxxxxxxxxxxx", i);
        if (!X509_NAME_add_entry_by_txt(nm, "OU", MBSTRING_ASC,
                                        (unsigned char *)ou, -1, -1, 0))
            goto err;
    }
    if (X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                                   (const unsigned char *)cn, -1, -1, 0))
        return nm;
 err:
    X509_NAME_free(nm);
    return NULL;
}

/*
 * Caching the extensions of a certificate with many relative distribution
 * points under a long issuer name must not build their full names: before
 * the fix every entry got its own copy of the issuer name here, on every
 * parse, whether or not a CRL was ever checked.
 */
static int test_crldp_names_deferred(void)
{
    EVP_PKEY *key = NULL;
    X509_NAME *name = NULL;
    X509 *x = NULL;
    X509_NAME *full = NULL;
    DIST_POINT *dp;
    int i, built = 0, ok = 0;

    if (!TEST_ptr(key = make_key())
        || !TEST_ptr(name = make_name("crldp-many", 60))
        || !TEST_ptr(x = make_cert(name, name, key, key, 1, 0, 400)))
        goto err;
    X509_check_purpose(x, -1, 0);
    if (!TEST_int_eq(sk_DIST_POINT_num(x->crldp), 400))
        goto err;
    for (i = 0; i < sk_DIST_POINT_num(x->crldp); i++) {
        dp = sk_DIST_POINT_value(x->crldp, i);
        if (dp->distpoint != NULL && dp->distpoint->type == 1
            && dp->distpoint->dpname != NULL)
            built++;
    }
    if (!TEST_int_eq(built, 0))
        goto err;

    /* The exported DIST_POINT_set_dpname() still builds the name on request */
    dp = sk_DIST_POINT_value(x->crldp, 0);
    if (!TEST_true(DIST_POINT_set_dpname(dp->distpoint, name))
        || !TEST_ptr(full = dp->distpoint->dpname)
        || !TEST_int_eq(X509_NAME_entry_count(full),
                        X509_NAME_entry_count(name) + 1))
        goto err;
    ok = 1;
 err:
    X509_free(x);
    X509_NAME_free(name);
    EVP_PKEY_free(key);
    return ok;
}

static X509_CRL *make_crl(X509_NAME *issuer, EVP_PKEY *signer,
                          const char *idp_cn, long revoked_serial)
{
    X509_CRL *crl = X509_CRL_new(), *ret = NULL;
    X509_REVOKED *rev = NULL;
    ISSUING_DIST_POINT *idp = NULL;
    ASN1_TIME *t = NULL;
    ASN1_INTEGER *serial = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    int len;

    if (crl == NULL
        || !X509_CRL_set_version(crl, 1)
        || !X509_CRL_set_issuer_name(crl, issuer)
        || (t = X509_gmtime_adj(NULL, -3600L)) == NULL
        || !X509_CRL_set1_lastUpdate(crl, t)
        || X509_gmtime_adj(t, 7 * 86400L) == NULL
        || !X509_CRL_set1_nextUpdate(crl, t)
        || (rev = X509_REVOKED_new()) == NULL
        || (serial = ASN1_INTEGER_new()) == NULL
        || !ASN1_INTEGER_set(serial, revoked_serial)
        || !X509_REVOKED_set_serialNumber(rev, serial)
        || X509_gmtime_adj(t, -60L) == NULL
        || !X509_REVOKED_set_revocationDate(rev, t)
        || !X509_CRL_add0_revoked(crl, rev))
        goto err;
    rev = NULL;
    if ((idp = ISSUING_DIST_POINT_new()) == NULL
        || (idp->distpoint = relative_dpname(idp_cn)) == NULL
        || !X509_CRL_add1_ext_i2d(crl, NID_issuing_distribution_point, idp,
                                  1, 0)
        || !X509_CRL_sort(crl)
        || X509_CRL_sign(crl, signer, EVP_sha256()) <= 0
        || (len = i2d_X509_CRL(crl, &der)) <= 0)
        goto err;
    p = der;
    ret = d2i_X509_CRL(NULL, &p, len);   /* sets the cached IDP name */
 err:
    OPENSSL_free(der);
    ISSUING_DIST_POINT_free(idp);
    ASN1_INTEGER_free(serial);
    ASN1_TIME_free(t);
    X509_REVOKED_free(rev);
    X509_CRL_free(crl);
    return ret;
}

/*
 * A leaf whose only distribution point is the relative name "CN=dp-1"
 * under its issuer, checked against CRLs whose issuing distribution point
 * is the same or another relative name.  The matching CRL must find the
 * leaf revoked; the other one is out of scope.  This exercises the name
 * that is now built on demand during CRL matching.
 */
static int verify_with_crl(const char *idp_cn, int *err)
{
    EVP_PKEY *cakey = NULL, *leafkey = NULL;
    X509_NAME *caname = NULL, *leafname = NULL;
    X509 *ca = NULL, *leaf = NULL;
    X509_CRL *crl = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    STACK_OF(X509_CRL) *crls = NULL;
    int ok = 0;

    if (!TEST_ptr(cakey = make_key())
        || !TEST_ptr(leafkey = make_key())
        || !TEST_ptr(caname = make_name("Carry Test CA", 0))
        || !TEST_ptr(leafname = make_name("carry-leaf", 0))
        || !TEST_ptr(ca = make_cert(caname, caname, cakey, cakey, 1, 1, 0))
        || !TEST_ptr(leaf = make_cert(leafname, caname, leafkey, cakey, 7, 0,
                                      2))
        || !TEST_ptr(crl = make_crl(caname, cakey, idp_cn, 7))
        || !TEST_ptr(store = X509_STORE_new())
        || !TEST_true(X509_STORE_add_cert(store, ca))
        || !TEST_ptr(crls = sk_X509_CRL_new_null())
        || !TEST_true(sk_X509_CRL_push(crls, crl))
        || !TEST_ptr(ctx = X509_STORE_CTX_new())
        || !TEST_true(X509_STORE_CTX_init(ctx, store, leaf, NULL)))
        goto err;
    X509_STORE_CTX_set0_crls(ctx, crls);
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK);
    (void)X509_verify_cert(ctx);
    *err = X509_STORE_CTX_get_error(ctx);
    ok = 1;
 err:
    X509_STORE_CTX_free(ctx);
    sk_X509_CRL_free(crls);
    X509_STORE_free(store);
    X509_CRL_free(crl);
    X509_free(leaf);
    X509_free(ca);
    X509_NAME_free(leafname);
    X509_NAME_free(caname);
    EVP_PKEY_free(leafkey);
    EVP_PKEY_free(cakey);
    return ok;
}

static int test_crldp_relative_match(void)
{
    int err = -1;

    /* "dp-1" is the leaf's second distribution point (dp-0, dp-1) */
    return verify_with_crl("dp-1", &err)
           && TEST_int_eq(err, X509_V_ERR_CERT_REVOKED);
}

static int test_crldp_relative_mismatch(void)
{
    int err = -1;

    if (!verify_with_crl("dp-9", &err))
        return 0;
    TEST_info("out-of-scope CRL: verify error %d (%s)", err,
              X509_verify_cert_error_string(err));
    return TEST_int_ne(err, X509_V_OK)
           && TEST_int_ne(err, X509_V_ERR_CERT_REVOKED);
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_uni2utf8, OSSL_NELEM(uni2utf8_cases));
    ADD_ALL_TESTS(test_p12_friendlyname, OSSL_NELEM(friendly_names));
    ADD_TEST(test_crldp_names_deferred);
    ADD_TEST(test_crldp_relative_match);
    ADD_TEST(test_crldp_relative_mismatch);
    return 1;
}
