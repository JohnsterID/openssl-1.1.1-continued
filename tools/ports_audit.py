#!/usr/bin/env python3
"""Three-way audit of the 1.1.1 ports 0003-0006 (B08, readiness plan step L14).

For every hunk of our port, against each reference series (cPanel/CloudLinux `ea-openssl11` 1.1.1w patches,
Ubuntu jammy 3.0.2 ports, OpenSSL's upstream 3.4 commits), the hunk is classified as:

  identical   its changed lines appear, in order, in the reference's changed lines for the same file
              (whitespace collapsed);
  cosmetic    equal after removing comments and joining wrapped lines (`comments/wrapping`), or after also
              normalising API names (`api-names`: the `ossl_` prefix, ERR_raise(ERR_LIB_X, R) against
              Xerr(X_F_..., R), and the per-port aliases listed in the manifest);
  semantic    anything else. Each semantic difference needs a reviewed explanation (--explanations); one
              without an explanation makes the audit fail ("unexplained").

Test files (`test/...`) are reported as test coverage, not classified. Hunks of a file that the reference
does not touch are `absent` (with the reference's file mapping in the manifest, e.g. 3.4's
ssl/record/methods/tls1_meth.c for 1.1.1's ssl/t1_enc.c).

  openssl_ports_audit.py --manifest M.json [--explanations E.json] [--json OUT.json] [--markdown OUT.md]

The manifest names the patch files; nothing is fetched. Exit 0 when no semantic difference is left
unexplained, 1 otherwise.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import sys

TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|0[xX][0-9A-Fa-f]+|\d+[uUlL]*|->|\+\+|--|&&|\|\||[<>=!]=|<<|>>|\S")
ERR_CALL = re.compile(r"\b(?:ERR_raise(?:_data)?|[A-Z0-9]+err)\s*\(\s*[A-Za-z0-9_]+\s*,\s*([A-Za-z0-9_]+)\s*(?:,[^;]*)?\)")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def parse_patch(text):
    """[{file, header, minus: [..], plus: [..]}] in patch order (git or quilt format)."""
    hunks, cur_file, cur = [], None, None
    for line in text.splitlines():
        if line.startswith("diff ") or line.startswith("--- "):
            cur = None
            continue
        if line.startswith("+++ "):
            path = line[4:].split("\t")[0].strip()
            cur_file = None if path == "/dev/null" else (path[2:] if path.startswith("b/") else path)
            cur = None
            continue
        if line.startswith("@@"):
            cur = {"file": cur_file, "header": line, "minus": [], "plus": []}
            hunks.append(cur)
            continue
        if cur is None:
            continue
        if line in ("-- ", "--"):  # format-patch signature
            cur = None
        elif line.startswith("-"):
            cur["minus"].append(line[1:])
        elif line.startswith("+"):
            cur["plus"].append(line[1:])
    return [h for h in hunks if h["minus"] or h["plus"]]


def squash(lines):
    return [re.sub(r"\s+", " ", x).strip() for x in lines if x.strip()]


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"/\*.*$", " ", text, flags=re.S)        # a comment opened in the hunk
    text = re.sub(r"^.*?\*/", " ", text, flags=re.S)       # a comment closed in the hunk
    text = re.sub(r"//[^\n]*", " ", text)
    return "\n".join(x for x in text.splitlines() if not re.match(r"^\s*\*", x))


def tokens(lines, api=False, aliases=None):
    text = strip_comments("\n".join(lines))
    if api:
        text = ERR_CALL.sub(lambda m: f"ERR({m.group(1)})", text)
    toks = TOKEN.findall(text)
    if api:
        aliases = aliases or {}
        toks = [aliases.get(t, t) for t in toks]
        toks = [t[5:] if t.startswith("ossl_") else t for t in toks]
    return toks


def contains(seq, sub):
    if not sub:
        return True
    n = len(sub)
    return any(seq[i:i + n] == sub for i in range(len(seq) - n + 1))


def in_order(seq, sub):
    it = iter(seq)
    return all(any(x == y for y in it) for x in sub)


def best_window(ref, sub):
    """The reference token window most similar to sub, and the token diff."""
    if not ref:
        return 0.0, []
    n = max(len(sub), 1)
    best = (0.0, 0)
    step = max(1, n // 8)
    for i in range(0, max(1, len(ref) - n + 1), step):
        r = difflib.SequenceMatcher(None, ref[i:i + n], sub, autojunk=False).ratio()
        if r > best[0]:
            best = (r, i)
    window = ref[best[1]:best[1] + n]
    diff = [d for d in difflib.ndiff(window, sub) if d[:1] in "+-"]
    return round(best[0], 3), diff[:40]


def classify(hunk, ref_hunks, aliases):
    """Classify one of our hunks against the reference's hunks for the same file."""
    if not ref_hunks:
        return {"class": "absent"}
    ref_minus = [x for h in ref_hunks for x in h["minus"]]
    ref_plus = [x for h in ref_hunks for x in h["plus"]]
    if in_order(squash(ref_minus), squash(hunk["minus"])) and in_order(squash(ref_plus), squash(hunk["plus"])):
        return {"class": "identical"}
    for level, api in (("comments/wrapping", False), ("api-names", True)):
        a_m, a_p = tokens(hunk["minus"], api, aliases), tokens(hunk["plus"], api, aliases)
        r_m, r_p = tokens(ref_minus, api, aliases), tokens(ref_plus, api, aliases)
        if contains(r_m, a_m) and contains(r_p, a_p):
            return {"class": "cosmetic", "level": level}
    a_p, r_p = tokens(hunk["plus"], True, aliases), tokens(ref_plus, True, aliases)
    a_m, r_m = tokens(hunk["minus"], True, aliases), tokens(ref_minus, True, aliases)
    rp, dp = best_window(r_p, a_p)
    rm, dm = best_window(r_m, a_m)
    return {"class": "semantic", "similarity_plus": rp, "similarity_minus": rm,
            "token_diff_plus": dp, "token_diff_minus": dm}


def hunk_id(port, i, h):
    return f"{port}#{i}:{h['file']}"


def audit(manifest, explanations):
    out = {"schema": "openssl-ports-audit/1", "ports": [], "unexplained": [], "counts": {}}
    counts = {}
    for port in manifest["ports"]:
        ours_text = Path(port["ours"]).read_text(errors="replace")
        ours = parse_patch(ours_text)
        refs = {}
        for name, paths in port["refs"].items():
            hunks = []
            for p in paths:
                hunks += parse_patch(Path(p).read_text(errors="replace"))
            refs[name] = hunks
        aliases = port.get("aliases", {})
        maps = port.get("path_map", {})
        entry = {"patch": port["patch"], "cve": port["cve"], "ours": {"path": port["ours"], "sha256": sha256(port["ours"])},
                 "refs": {n: [{"path": p, "sha256": sha256(p)} for p in ps] for n, ps in port["refs"].items()},
                 "hunks": [], "tests": {}}
        for i, h in enumerate(ours):
            if h["file"].startswith("test/"):
                t = entry["tests"].setdefault(h["file"], {"plus_lines": 0, "in": []})
                t["plus_lines"] += len(h["plus"])
                continue
            hid = hunk_id(port["patch"], i, h)
            row = {"id": hid, "file": h["file"], "header": h["header"], "minus": len(h["minus"]),
                   "plus": len(h["plus"]), "vs": {}}
            for name, rhunks in refs.items():
                target = maps.get(name, {}).get(h["file"], h["file"])
                same = [r for r in rhunks if r["file"] == target]
                res = classify(h, same, aliases)
                if target != h["file"]:
                    res["ref_file"] = target
                key = f"{hid}@{name}"
                if res["class"] in ("semantic", "absent"):
                    exp = explanations.get(key)
                    if exp:
                        res["explanation"] = exp
                    else:
                        out["unexplained"].append(key)
                row["vs"][name] = res
                counts.setdefault(name, {}).setdefault(res["class"], 0)
                counts[name][res["class"]] += 1
            entry["hunks"].append(row)
        # the other direction: every code hunk of a reference must be covered by our port
        entry["reference_only"] = []
        for name, rhunks in refs.items():
            inverse = {v: k for k, v in maps.get(name, {}).items()}
            for j, r in enumerate(rhunks):
                if r["file"] is None or r["file"].startswith("test/"):
                    continue
                ours_file = inverse.get(r["file"], r["file"])
                mine = [h for h in ours if h["file"] == ours_file]
                m_minus = tokens([x for h in mine for x in h["minus"]], True, aliases)
                m_plus = tokens([x for h in mine for x in h["plus"]], True, aliases)
                if contains(m_minus, tokens(r["minus"], True, aliases)) and \
                        contains(m_plus, tokens(r["plus"], True, aliases)):
                    continue
                key = f"{port['patch']}:{name}#{j}:{r['file']}"
                item = {"id": key, "ref": name, "file": r["file"], "header": r["header"],
                        "minus": len(r["minus"]), "plus": len(r["plus"])}
                exp = explanations.get(key)
                if exp:
                    item["explanation"] = exp
                else:
                    out["unexplained"].append(key)
                entry["reference_only"].append(item)
        for name, rhunks in refs.items():
            for f in entry["tests"]:
                if any(r["file"] == f for r in rhunks):
                    entry["tests"][f]["in"].append(name)
        out["ports"].append(entry)
    out["counts"] = counts
    stale = sorted(set(explanations) - {f"{h['id']}@{n}" for p in out["ports"] for h in p["hunks"] for n in h["vs"]
                                        if h["vs"][n]["class"] in ("semantic", "absent")})
    stale = [s for s in stale if s not in {r["id"] for p in out["ports"] for r in p["reference_only"]}]
    out["stale_explanations"] = stale
    out["verdict"] = "no unexplained semantic difference" if not out["unexplained"] else "unexplained differences"
    return out


def markdown(res, title):
    lines = [f"# {title}", "",
             "Each hunk of our 1.1.1 port is compared with the cPanel/CloudLinux `ea-openssl11` patch "
             "(1.1.1w), Ubuntu's jammy 3.0.2 port and OpenSSL's 3.4 commit. **identical**: the same changed "
             "lines; **cosmetic**: equal after removing comments and wrapping (`c/w`) or after also normalising "
             "API names (`api`: the `ossl_` prefix, `ERR_raise(ERR_LIB_X, R)` against `Xerr(X_F_..., R)`); "
             "**semantic**: anything else, each with a reviewed explanation; **absent**: the reference does not "
             "change that file. Test files are listed separately.", "",
             f"**Verdict: {res['verdict']}.**", ""]
    names = sorted({n for p in res["ports"] for h in p["hunks"] for n in h["vs"]})
    lines += ["| Reference | " + " | ".join(["identical", "cosmetic", "semantic", "absent"]) + " |",
              "|---|---|---|---|---|"]
    for n in names:
        c = res["counts"].get(n, {})
        lines.append(f"| {n} | {c.get('identical', 0)} | {c.get('cosmetic', 0)} | {c.get('semantic', 0)} | "
                     f"{c.get('absent', 0)} |")
    lines.append("")

    def cell(v):
        if v["class"] == "cosmetic":
            return "cosmetic (" + ("c/w" if v["level"] == "comments/wrapping" else "api") + ")"
        if v["class"] in ("semantic", "absent"):
            label = "**semantic**" if v["class"] == "semantic" else "absent"
            return label + (", explained" if v.get("explanation") else ", **UNEXPLAINED**")
        return v["class"] + (f" ({v['ref_file']})" if v.get("ref_file") else "")

    for p in res["ports"]:
        lines += [f"## {p['patch']}: {p['cve']}", "",
                  f"Ours: `{Path(p['ours']['path']).name}` (sha256 `{p['ours']['sha256'][:16]}…`). References: "
                  + "; ".join(f"{n}: " + ", ".join(f"`{Path(x['path']).name}`" for x in xs) for n, xs in p["refs"].items()),
                  "", "| Hunk | File | -/+ | " + " | ".join(names) + " |", "|---|---|---|" + "---|" * len(names)]
        for h in p["hunks"]:
            lines.append(f"| {h['id'].split(':')[0]} | `{h['file']}` | {h['minus']}/{h['plus']} | "
                         + " | ".join(cell(h["vs"][n]) if n in h["vs"] else "—" for n in names) + " |")
        lines.append("")
        exps = [(h["id"], n, h["vs"][n]) for h in p["hunks"] for n in names
                if n in h["vs"] and h["vs"][n]["class"] in ("semantic", "absent")]
        for hid, n, v in exps:
            lines.append(f"- `{hid}` vs {n}: {v.get('explanation', 'UNEXPLAINED')}")
        if exps:
            lines.append("")
        for r in p["reference_only"]:
            lines.append(f"- reference-only hunk `{r['id']}` ({r['minus']}/{r['plus']} lines): "
                         f"{r.get('explanation', 'UNEXPLAINED')}")
        if p["reference_only"]:
            lines.append("")
        if p["tests"]:
            lines.append("Tests: " + "; ".join(f"`{f}` +{t['plus_lines']} lines (also in: {', '.join(t['in']) or 'none'})"
                                               for f, t in p["tests"].items()))
            lines.append("")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--explanations", type=Path)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--markdown", type=Path)
    ap.add_argument("--title", default="Ports audit: 1.1.1zi carry fixes 3-6")
    a = ap.parse_args(argv)
    manifest = json.loads(a.manifest.read_text())
    exps = json.loads(a.explanations.read_text()) if a.explanations else {}
    res = audit(manifest, exps)
    if a.json:
        a.json.write_text(json.dumps(res, indent=1) + "\n")
    if a.markdown:
        a.markdown.write_text(markdown(res, a.title))
    print(json.dumps({"verdict": res["verdict"], "counts": res["counts"], "unexplained": res["unexplained"],
                      "stale_explanations": res["stale_explanations"]}, indent=1))
    return 0 if not res["unexplained"] else 1


if __name__ == "__main__":
    sys.exit(main())
