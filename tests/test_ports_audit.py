#!/usr/bin/env python3
import json
from pathlib import Path
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import ports_audit as pa  # noqa: E402



def patch(path, *hunks, signature=True):
    out = [f"diff --git a/{path} b/{path}", f"--- a/{path}", f"+++ b/{path}"]
    for h in hunks:
        out.append("@@ -1,3 +1,4 @@ ctx")
        out += [" context"] + h + [" context"]
    if signature:
        out += ["-- ", "2.43.0"]
    return "\n".join(out) + "\n"


OURS = ["+    if (bn_wexpand(a, words) == NULL)", "+        return 0;", "+    /* pin the top */", "+    a->top = words;"]


class AuditTests(unittest.TestCase):
    def run_audit(self, ours, refs, explanations=None, extra=None):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "ours.patch").write_text(ours)
            rp = {}
            for name, text in refs.items():
                Path(d, name + ".patch").write_text(text)
                rp[name] = [str(Path(d, name + ".patch"))]
            port = {"patch": "0003", "cve": "CVE-X", "ours": str(Path(d, "ours.patch")), "refs": rp}
            port.update(extra or {})
            return pa.audit({"ports": [port]}, explanations or {})

    def vs(self, res, name):
        return res["ports"][0]["hunks"][0]["vs"][name]

    def test_identical(self):
        res = self.run_audit(patch("crypto/bn/bn_intern.c", OURS), {"r": patch("crypto/bn/bn_intern.c", OURS)})
        self.assertEqual(self.vs(res, "r")["class"], "identical")
        self.assertEqual(res["unexplained"], [])

    def test_signature_is_not_a_removed_line(self):
        res = self.run_audit(patch("f.c", OURS), {"r": patch("f.c", OURS, signature=False)})
        self.assertEqual(res["ports"][0]["hunks"][0]["minus"], 0)
        self.assertEqual(self.vs(res, "r")["class"], "identical")

    def test_comment_and_wrapping_is_cosmetic(self):
        ref = ["+    if (bn_wexpand(a,", "+                   words) == NULL)", "+        return 0;",
               "+    /* a different comment */", "+    a->top = words;"]
        res = self.run_audit(patch("f.c", OURS), {"r": patch("f.c", ref)})
        self.assertEqual(self.vs(res, "r"), {"class": "cosmetic", "level": "comments/wrapping"})

    def test_api_names_are_cosmetic(self):
        ours = ["+    ECerr(EC_F_EC_SCALAR_MUL_LADDER, ERR_R_BN_LIB);", "+    ec_scalar_mul_ladder(g, r);"]
        ref = ["+    ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);", "+    ossl_ec_scalar_mul_ladder(g, r);"]
        res = self.run_audit(patch("f.c", ours), {"r": patch("f.c", ref)})
        self.assertEqual(self.vs(res, "r"), {"class": "cosmetic", "level": "api-names"})

    def test_semantic_needs_an_explanation(self):
        ref = ["+    if (bn_wexpand(a, words) == NULL)", "+        return 1;", "+    a->top = words;"]
        res = self.run_audit(patch("f.c", OURS), {"r": patch("f.c", ref)})
        self.assertEqual(self.vs(res, "r")["class"], "semantic")
        self.assertEqual(res["unexplained"], ["0003#0:f.c@r", "0003:r#0:f.c"])
        self.assertEqual(res["verdict"], "unexplained differences")
        res = self.run_audit(patch("f.c", OURS), {"r": patch("f.c", ref)},
                             {"0003#0:f.c@r": "x", "0003:r#0:f.c": "y"})
        self.assertEqual(res["unexplained"], [])
        self.assertEqual(res["verdict"], "no unexplained semantic difference")

    def test_absent_file_needs_an_explanation(self):
        res = self.run_audit(patch("ssl/t1_enc.c", OURS), {"r": patch("ssl/other.c", OURS)})
        self.assertEqual(self.vs(res, "r")["class"], "absent")
        self.assertIn("0003#0:ssl/t1_enc.c@r", res["unexplained"])

    def test_path_map(self):
        res = self.run_audit(patch("ssl/t1_enc.c", OURS), {"r": patch("ssl/record/methods/tls1_meth.c", OURS)},
                             extra={"path_map": {"r": {"ssl/t1_enc.c": "ssl/record/methods/tls1_meth.c"}}})
        self.assertEqual(self.vs(res, "r")["class"], "identical")
        self.assertEqual(res["unexplained"], [])

    def test_reference_only_hunk_is_flagged(self):
        extra_hunk = ["+    constant_time_select_bn(m, a, b);"]
        res = self.run_audit(patch("f.c", OURS), {"r": patch("f.c", OURS, extra_hunk)})
        self.assertEqual(self.vs(res, "r")["class"], "identical")
        self.assertEqual(res["unexplained"], ["0003:r#1:f.c"])

    def test_tests_are_listed_not_classified(self):
        text = patch("f.c", OURS) + patch("test/x.c", ["+    TEST_true(1);"])
        res = self.run_audit(text, {"r": patch("f.c", OURS) + patch("test/x.c", ["+ other"])})
        self.assertEqual(len(res["ports"][0]["hunks"]), 1)
        self.assertEqual(res["ports"][0]["tests"]["test/x.c"]["in"], ["r"])


if __name__ == "__main__":
    unittest.main()
