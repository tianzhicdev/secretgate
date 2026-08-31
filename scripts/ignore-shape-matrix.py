#!/usr/bin/env python3
"""c125 ignore-pattern SHAPE matrix — B c109 offer shipped + a bigger find.

Cells C1-C10 + flip F1 + vacuity V1 + rail legs R1/R2, table frozen in the
c125 cycle's EXPECT.md BEFORE implementation. Pins the engine's
is_ignored contract per SHAPE (the engine that suppressed my fleet's
evidence dirs had zero shape tests: one form inert, one an over-bless —
both measured before touched), and the dead-ref-check B-leg's new AUTHORITY
leg: liveness is judged by the engine's own is_ignored loaded by path,
never by a re-implemented approximation.

Old-gen escape reproduction (C3) reads `git show v1.2.6:secretgate.py` —
the escape is proven against the real released bytes, not a hand-copy
(c39 law). Mutants are py_compile-gated BEFORE drive (c121 law) and mutate
the ENTRY GATE, not an error body (C c116 law).

Run from the secretgate repo root. Exit 0 all cells pass; 1 names fails;
2 bad usage / engine load failure (fail-closed).
"""
import importlib.util
import os
import py_compile
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ENGINE = os.path.join(ROOT, "secretgate.py")
DRC = os.path.join(ROOT, "scripts", "dead-ref-check.py")
OLD_REF = "v1.2.6"   # last RELEASED gen = the bytes every consumer runs today
fails = 0
total = 0

# --- mutation sites (unique strings inside the c125 window branch) --------
F1_SITE = """elif len(pseg) <= len(parts) and all(
                    fnmatch(parts[-len(pseg) + i], pseg[i])
                    for i in range(len(pseg))):"""
F1_NEW = "elif fnmatch(rel_path, pat):  # mutant: old whole-rel bless back"
V1_SITE = """                if fnmatch(rel_path, pat) or any(fnmatch(p, pat) for p in parts):"""
V1_NEW = """                if fnmatch(rel_path, pat):  # mutant: bare-seg glob arm dropped"""


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"cannot load: {path}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cell(name, got, want):
    global fails, total
    total += 1
    ok = got == want
    print(("PASS " if ok else "FAIL ") + name + f" (got={got} want={want})")
    if not ok:
        fails += 1


def mutant(old, new, name):
    """single-site mutation of the SHIPPED source, py_compile-gated (c121)."""
    src = open(ENGINE).read()
    assert src.count(old) == 1, f"{name}: mutation site not unique ({src.count(old)})"
    p = os.path.join(tempfile.mkdtemp(prefix="c125mut-"), "secretgate_m.py")
    with open(p, "w") as fh:
        fh.write(src.replace(old, new))
    py_compile.compile(p, doraise=True)
    return load(p, "sg_mut_" + name)


def main():
    global fails
    if not os.path.isfile(ENGINE):
        print("run from the secretgate repo root", file=sys.stderr)
        return 2
    sg = load(ENGINE, "sg_ship")
    old = subprocess.run(["git", "-C", ROOT, "show", f"{OLD_REF}:secretgate.py"],
                         capture_output=True, text=True, check=True,
                         timeout=60).stdout
    old_path = os.path.join(tempfile.mkdtemp(prefix="c125old-"), "secretgate.py")
    with open(old_path, "w") as fh:
        fh.write(old)
    sgo = load(old_path, "sg_old")

    # C1 (contract pin, B c109): full-path dir pattern is INERT by design —
    # dir/ form fnmatches single segments; a '/' can never equal one.
    # Fail-SAFE direction (re-scan, never bless); documented in README.
    cell("C1 full-path dir pat INERT (documented contract)",
         sg.is_ignored("agents/B/work/x-dir/RESULT.md", ["agents/B/work/x-dir/"]), False)
    # C2: bare-segment dir form matches at any depth.
    cell("C2 bare-seg dir pat any depth",
         sg.is_ignored("p/q/x-dir/f", ["x-dir/"]), True)
    # C3: OLD released gen's over-bless REPRODUCED on its own bytes.
    cell("C3 old-gen over-bless reproduced (tests/*.b64 -> tests/deep/)",
         sgo.is_ignored("tests/deep/x.b64", ["tests/*.b64"]), True)
    # C4: shipped gen closes it (README's own example can no longer bless).
    cell("C4 shipped: tests/*.b64 must NOT reach tests/deep/x.b64",
         sg.is_ignored("tests/deep/x.b64", ["tests/*.b64"]), False)
    # C5: the depth the user actually wrote stays alive.
    cell("C5 shipped: tests/x.b64 still matches",
         sg.is_ignored("tests/x.b64", ["tests/*.b64"]), True)
    # C6: any-depth suffix alignment (documented divergence, README'd).
    cell("C6 shipped: z/tests/x.b64 aligns (suffix window)",
         sg.is_ignored("z/tests/x.b64", ["tests/*.b64"]), True)
    # C7: bare glob segment shape unchanged.
    cell("C7 shipped: bare glob v11-*.py at depth",
         sg.is_ignored("logs/v11-q.py", ["v11-*.py"]), True)
    # C8: c114 empty-pattern contract regression.
    cell("C8 empty/whitespace pattern inert",
         sg.is_ignored("a/b/", ["", "   "]), False)
    # C9: exact path, no wildcards.
    cell("C9 exact full path match",
         sg.is_ignored("scripts/pin-verify.py", ["scripts/pin-verify.py"]), True)
    # C10: len==1 glob keeps full-rel shape (no slash in pattern).
    cell("C10 *.log at depth (len==1 glob)",
         sg.is_ignored("a/b/x.log", ["*.log"]), True)

    # F1 FLIP: revert the window condition to the old whole-rel fnmatch ->
    # the C4 world escapes back to True. The window IS the tooth.
    m = mutant(F1_SITE, F1_NEW, "F1")
    cell("F1 flip: window-reverted mutant re-blesses tests/deep/x.b64",
         m.is_ignored("tests/deep/x.b64", ["tests/*.b64"]), True)

    # V1 VACUITY control: drop the bare-segment glob arm -> C7's world goes
    # False. Proves the matrix sees more than the F1 cell.
    m2 = mutant(V1_SITE, V1_NEW, "V1")
    cell("V1 vacuity: bare-seg-arm-removed mutant REDS the C7 world",
         m2.is_ignored("logs/v11-q.py", ["v11-*.py"]), False)

    # R1/R2: dead-ref-check's B-leg judges liveness with the ENGINE's
    # is_ignored loaded by path (public helper probed here).
    drc = load(DRC, "drc_c125")
    if not hasattr(drc, "pattern_is_live"):
        print("FAIL R1/R2 dead-ref-check exposes no pattern_is_live() "
              "(authority leg missing)")
        fails += 2
    else:
        idx = ["agents/B/work/x-dir/RESULT.md", "p/q/y-dir/f", "top.txt"]
        cell("R1 rail authority: full-path dir pat judged DEAD",
             drc.pattern_is_live("agents/B/work/x-dir/", idx), False)
        cell("R2 rail authority: bare-seg dir pat judged LIVE",
             drc.pattern_is_live("y-dir/", idx), True)

    print(f"ignore-shape matrix: {total - fails}/{total} cells pass")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
