#!/usr/bin/env python3
"""c114 library-empty-pattern matrix (C c109 law: audit the PARAMETER at
every layer that can receive it, not the FLAG at the one layer you ship).

Defect class (measured at v1.2.5; leg saves in the c114 evidence dir,
legs-raw.txt): is_ignored('dir/', ['']) -> True. An EMPTY pattern string
suppressed any path whose last segment was empty (trailing-slash paths), and
glob-empty forms like ['*/'] suppressed every nested path. The file door was
never reachable (load_ignore_patterns filters blank lines) and the CLI has no
--ignore flag — the SUPPRESSION door was the IMPORT door only: a library
caller building the pattern list by hand (raw splitlines(), ported CI glue)
blessed files the scanner should have opened. Direction of the bless:
SUPPRESSION (false clean) — the same fail-open family as the v1.0/v1.1
empty---require class C closed at the args layer, at this repo's parameter
layer. Fix v1.2.6-dev: empty/whitespace patterns are INERT (refuse-to-match;
fail-SAFE direction: inert pattern -> re-scan, never a bless).

Cells run BOTH generations: the pre-fix engine comes from `git show
v1.2.5:secretgate.py` (the tag's shipped bytes, not a copy), the post-fix
engine is this repo's working secretgate.py.
  E1 OLD is_ignored('dir/', ['']) == True        (bless repro on old bytes)
  E2 NEW is_ignored('dir/', ['']) == False       (inert)
  E3 NEW is_ignored('dir/', [' ']) == False      (whitespace inert too)
  E4 NEW real patterns unchanged: 'proofs/' dir form, 'doc.md' basename
     form, 'proofs/*' glob form all still True; 'config.py' stays False
     (non-vacuity: the matrix can go green, it is not rc!=0 love)
  E5 END-TO-END dir-prune shape, cause-isolated to the empty pattern alone
     (C c108 compound-cell law bit my own first draft — see comment there):
     OLD -> subtree pruned (false clean), NEW -> walked + plant scans red.
  E6 measured ['*/'] glob-empty surface adjudicated: authored glob kept
     (correct gitignore semantics), logged in REPORT LEARNED.
Exits 1 naming any failed cell; prints one line per cell.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PINNED_TAG = "v1.2.5"


def load_engine(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"cannot load engine: {path}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def old_engine_bytes():
    return subprocess.run(["git", "-C", ROOT, "show", f"{PINNED_TAG}:secretgate.py"],
                          capture_output=True, text=True, check=True,
                          timeout=60).stdout


old_src = old_engine_bytes()
old_path = os.path.join(tempfile.mkdtemp(prefix="sg-old-"), "secretgate.py")
with open(old_path, "w") as fh:
    fh.write(old_src)
old = load_engine(old_path, "sg_old")
new = load_engine(os.path.join(ROOT, "secretgate.py"), "sg_new")

failures = []


def cell(name, got, want):
    ok = got == want
    print(f"{'ok  ' if ok else 'FAIL'} {name}: got {got!r} want {want!r}")
    if not ok:
        failures.append(name)


# E1-E3: the bless repro and its closure
cell("E1 old blesses trailing-slash path vs empty pattern", old.is_ignored("dir/", [""]), True)
cell("E2 new inert for empty pattern", new.is_ignored("dir/", [""]), False)
cell("E3 new inert for whitespace pattern", new.is_ignored("dir/", [" "]), False)

# E4: non-vacuity — real patterns must keep working on the NEW engine
cell("E4a dir form still ignores", new.is_ignored("proofs/x.md", ["proofs/"]), True)
cell("E4b basename form still ignores", new.is_ignored("a/b/doc.md", ["doc.md"]), True)
cell("E4c glob form still ignores", new.is_ignored("proofs/x.md", ["proofs/*"]), True)
cell("E4d unpatterned path stays scannable", new.is_ignored("config.py", ["proofs/"]), False)

# E5: end-to-end SUPPRESSION, old vs new, one suppression CAUSE per fixture
# (C c108 compound-cell law — my first draft seeded ['','sub/'] and 'sub/'
# matched via its dir-arm as designed, conflating causes; the matrix caught
# it). Isolated cause: a hand-rolled walk-pruning caller checks the DIR name
# before descending — `if not is_ignored(d + '/', pats)` — and a raw
# splitlines() pattern list carries a blank entry. Old gen: the empty
# pattern equals the path's empty last segment -> ENTIRE SUBTREE skipped ->
# false clean. New gen: empty pattern inert -> subtree walked, plant found.
plant_line = "api_key = " + repr("".join(["AKIA", "1234", "5678", "90AB", "CDEF", "Zz9X"]))
pats_raw = [""]  # blank line survived raw splitlines() — the sole cause under test
for label, eng, want_pruned in (("E5-old", old, True), ("E5-new", new, False)):
    pruned = eng.is_ignored("sub/", pats_raw)  # dir-prune decision shape
    cell(f"{label} dir-prune state (cause-isolated: empty pattern only)", pruned, want_pruned)
    if not want_pruned:
        # not pruned => the walker opens sub/ and the plant scans red:
        findings = len(eng.scan_text(plant_line, "sub/x"))
        cell(f"{label} plant scanned red when not pruned", findings > 0, True)

# E6: the OTHER measured bless surface from legs-raw.txt: ['*/'] (glob form
# of an empty dir name) suppressed EVERY nested path on old bytes.
cell("E6-old glob-empty suppressed nested path", old.is_ignored("sub/x", ["*/"]), True)
cell("E6-new glob-empty still matches a dir-named-empty path", new.is_ignored("sub/x", ["*/"]), True)
# Adjudication (logged, not silently fixed): '*/' as a HAND-WRITTEN pattern
# means 'every directory' and matching is correct gitignore semantics — the
# inert-blank guard covers '' and whitespace, NOT authored globs. A caller
# that PASSES ['*/'] authored that suppression. Recorded in REPORT LEARNED.

if failures:
    print(f"library-empty-matrix: {len(failures)} FAILED: {failures}")
    sys.exit(1)
print("library-empty-matrix: all cells pass (old bless repro + new closure + non-vacuity)")
