#!/usr/bin/env python3
"""Dead-reference rail (A c51 port of C c41): names that no longer name a file.

The artifact-hygiene rail (c50 / C c40) checks that no TRACKED file lacks a
referrer. This rail walks the inverse arrow: every REFERENCE a stranger or a
CI step follows must still name something that exists. A stale exclusion file,
a gitignore line that names a tracked file, or a README path that rotted after
a rename are all SILENT lies: nothing crashes, the reader just 404s or the
guard watches nothing. Same index-authority convention (git ls-files is the
truth of what exists; the disk is not).

Checks (exit 1 on any violation, exit 2 on missing inputs — fail-closed):
  A. README prose paths. Outside ``` fences, every inline-code token that is
     a path (contains '/', no '@', no leading 'tianzhicdev/' = external-repo
     ref) and every RELATIVE markdown link ](path) must resolve to a tracked
     FILE or a tracked-directory prefix. Fenced blocks are copy-paste
     snippets for the CONSUMER's repo, so prose-scope is the honest boundary
     — documented, not guessed. A c51 port addition: a path under `.git/` is
     skipped ONLY if the resolved rel is NOT itself tracked — hookpack
     documents `.git/hooks/pre-commit` + `.git/hookpack/cache/` in PROSE,
     and those are created at hook-install time in the READER's repo; they
     can never live in our index. The tracked-first order means a malicious
     or accidental `.git/...` path that DID get tracked is still checked —
     measured unreachable on git 2.43 (C c45 + A c54 re-derivation: `git add`
     and `add -f` silently ignore it, rc=0, zero entries; `update-index --add`
     prints 'Ignoring path'; `--cacheinfo` errors 'Invalid path' rc=128; a
     plumbing-crafted `.git` subtree passes `mktree` but dies at `read-tree`
     'invalid path', also via commit-tree + `reset --hard`). The order is
     therefore DEFENSE-IN-DEPTH, not a live gap — do not grow more code for
     the unreachable branch (unreachable branches are their own vacuity class).
  B. .secretgateignore liveness (if present): every non-comment pattern must
     match >=1 tracked path, using secretgate's real semantics (exact path,
     'dir/' prefix, or fnmatch). A pattern matching NOTHING is a dead
     exclusion — config drift that will silently stop meaning anything.
  C. .gitignore vs INDEX (if present): no TRACKED path may match an active
     (un-negated) pattern — a gitignore line naming a tracked file is the
     C c40 accident in its latent form: the ignore rule LIES because
     gitignore never untracks, and the file stays tracked + public while the
     config claims otherwise.

Stdlib only; git via subprocess; run from the repo root.
Source: agents/C/work/c41-dead-ref/dead-ref-check.py (ethkey-lite
8c4023e/ce410e5), ported with the .git/ leg above; all three A repos.
"""
import fnmatch
import posixpath
import re
import subprocess
import sys
from pathlib import Path

README = "README.md"
EXCLUDES = ".secretgateignore"
GITIGNORE = ".gitignore"
EXTERNAL_PREFIX = "tianzhicdev/"  # cross-repo refs, not repo-local paths
RUNTIME_DIR = ".git"  # created in the reader's repo at runtime


def is_runtime_scope(rel):
    """A c59 (C c50 V3 class + a live gap measured on own bytes):
    MEMBERSHIP-strict, not prefix-strict on the slash. Two measured
    truths this shape is the intersection of: (1) a bare `.git` ref in
    README prose is the SAME runtime dir as `.git/hooks/x` — pre-fix
    the `.git/`-prefix carve-out false-RED'd it (rc=1 on own bytes);
    (2) a sloppy `.git` prefix (no slash) swallows `.github-secret/...`
    baits with rc=0 blessing (measured mutant). Identity-or-dir-child
    is the only shape that is both."""
    return rel == RUNTIME_DIR or rel.startswith(RUNTIME_DIR + "/")


def die(msg, code=1):
    print(f"FAIL: {msg}")
    sys.exit(code)


def ok(msg):
    print(f"OK: {msg}")


def tracked_files():
    r = subprocess.run(["git", "ls-files"], capture_output=True, text=True)
    if r.returncode != 0:
        die("git ls-files failed: " + r.stderr.strip(), 2)
    files = r.stdout.split()
    if not files:
        die("git ls-files returned zero paths (empty index? vacuous rail)", 2)
    return files


def tracked_dirs(files):
    dirs = set()
    for f in files:
        parts = f.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    return dirs


def read(path):
    p = Path(path)
    if not p.is_file():
        return None
    return p.read_text(encoding="utf-8")


def readme_prose(text):
    """README with ``` fenced blocks removed (odd-count fences are malformed
    -> fail-closed: a rail that guesses fence state is a rail that goes blind
    on the day someone forgets to close one)."""
    if text.count("```") % 2 != 0:
        die("README has an unterminated ``` fence — refusing to guess prose scope", 2)
    out, in_fence = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append(line)
    return "\n".join(out)


def ignore_patterns(text):
    return [l.strip() for l in text.splitlines()
            if l.strip() and not l.strip().startswith("#")]


def matches_ignore_pattern(pat, path):
    """Simplified gitignore/secretgate matching: exact, dir-prefix, or
    fnmatch on full path / basename ('*' does not cross '/')."""
    if pat.startswith("!"):
        return None  # negation: skip conservatively (none in use; documented)
    p = pat.rstrip("/")
    if path == p or path.startswith(p + "/"):
        return True
    base = path.split("/")[-1]
    if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(base, pat):
        return True
    return False


def main():
    files = tracked_files()
    dirs = tracked_dirs(files)
    fails = 0

    # --- A. README prose paths -------------------------------------------
    readme = read(README)
    if readme is None:
        die(f"{README} missing (this rail's primary surface — refusing vacuous OK)", 2)
    prose = readme_prose(readme)
    refs = []
    for m in re.finditer(r"`([^`\n]+)`", prose):
        s = m.group(1).strip()
        if "/" not in s or "@" in s or " " in s or s.startswith(EXTERNAL_PREFIX):
            continue
        if re.fullmatch(r"\.{0,2}/?[\w.\-]+(/[\w.\-]+)*/?", s):
            refs.append(s)
    for m in re.finditer(r"\]\((?!https?://|mailto:|#|/)([^)#\s]+)", prose):
        refs.append(m.group(1))
    seen, dead, runtime = set(), [], []
    # (dead-leg names the CANONICAL resolved form — c60, one form owns all
    # three sites: exempt print, scope assert, dead message.)
    for r_ in refs:
        stripped = r_[2:] if r_.startswith("./") else (r_[1:] if r_.startswith("/") else r_)
        # A c60 (B c47 traversal delta, MEASURED on own bytes): normalize
        # ONCE at collection. Pre-fix strip-only + rstrip("/"): a prose
        # ref `.git/../scripts/x` still startswith(".git/"), rode the
        # carve-out rc=0 BLESSED, and sat IN the printed exempt set (the
        # inlined scope literal is a string test too — it read the
        # traversal form as a member); a legit `scripts/../scripts/run.sh`
        # false-RED'd rc=1. posixpath.normpath is the ONE canonical form
        # the branch fn, the scope assert, and the dead-leg message all
        # read — no print-vs-check drift, and a ref that RESOLVES outside
        # .git/ can never be a member of the exempt set.
        rel = posixpath.normpath(stripped) if stripped else stripped
        # A c51: reader-runtime path (under .git/) is exempt ONLY after the
        # index said no — a tracked .git/... path is still RED.
        # A c56 (B c45 causal note): the exemption branch fires BEFORE the
        # seen-set — pre-fix my c55 port added to seen FIRST, so exempted
        # refs inflated the printed checked-count (measured on own bytes:
        # 1 file ref + 2 runtime refs printed '3 checked'; the exact number
        # a dead-ref-riding-the-carve-out fakes).
        if is_runtime_scope(rel) and rel not in files:
            runtime.append(rel)
            continue
        if rel in seen:
            continue
        seen.add(rel)
        if rel in files or rel in dirs:
            continue
        dead.append(rel)
    # A c56 (B c45 offer, 3-line scope-assert): every exempted name must
    # normalize to a .git/ first component, else it's a dead ref riding the
    # carve-out — RED by rc, naming it. The printed names made this verdict
    # expressible; a count alone cannot say 'this name is wrong'.
    # A c59 (C c50 V3 delta): the assert is a SEPARATE authority from the
    # branch — inlined literal, NOT is_runtime_scope(). A mutant that
    # widens the shared predicate (measured: constant-edit to sloppy
    # '.git' blessed .github* baits with BOTH sites reading one constant)
    # is named by this literal instead of going blind with it.
    over = [n for n in sorted(set(runtime))
            if not (n == ".git" or n.startswith(".git/"))]
    for n in over:
        print(f"FAIL: runtime-scope exemption outside .git/ carve-out: {n}")
        fails += 1
    for d in dead:
        print(f"FAIL: README references a path that is not tracked: {d}")
        fails += 1
    if not dead and not over:
        # c55 strengthen (C c45 offer, A's own c51 rule turned back on my
        # rail): the exemption prints its count AND the names — a printed
        # count nothing asserts is still an rc-only GREEN; naming the set
        # is what lets a flip assert the carve-out fired on EXACTLY its
        # mutation (exempt-everything and silent-skip mutants both stay
        # rc=0 under a count-only assert). A c56: exempted refs are no
        # longer counted in `seen` (B c45 order fix) — checked == real
        # file/dir refs only.
        uniq_rt = sorted(set(runtime))
        ok(f"README prose paths all resolve ({len(seen)} checked: files + dirs"
           + (f"; runtime-scope .git/ exemptions: {len(uniq_rt)}"
              f" [{', '.join(uniq_rt)}]" if uniq_rt else
              "; runtime-scope .git/ exemptions: 0") + ")")

    # --- B. .secretgateignore liveness ------------------------------------
    ex = read(EXCLUDES)
    if ex is None:
        ok(f"{EXCLUDES} absent — layer skipped by design (scan strict by default)")
    else:
        pats = ignore_patterns(ex)
        dead_pats = [p for p in pats
                     if not any(matches_ignore_pattern(p, f) for f in files)]
        for p in dead_pats:
            print(f"FAIL: {EXCLUDES} pattern matches ZERO tracked paths: {p}")
            fails += 1
        if not dead_pats:
            ok(f"{EXCLUDES}: all {len(pats)} exclusions match >=1 tracked path")

    # --- C. .gitignore vs INDEX --------------------------------------------
    gi = read(GITIGNORE)
    if gi is None:
        ok(f"{GITIGNORE} absent — layer skipped by design")
    else:
        pats = ignore_patterns(gi)
        conflicts = []
        for p in pats:
            if p.endswith("/"):
                continue  # dir-only pattern can't match an index entry
            hits = [f for f in files if matches_ignore_pattern(p, f)]
            if hits:
                conflicts.append((p, hits))
        for p, hits in conflicts:
            print(f"FAIL: {GITIGNORE} pattern '{p}' names TRACKED file(s) "
                  f"(gitignore never untracks — C c40 class): {', '.join(sorted(hits)[:5])}")
            fails += 1
        if not conflicts:
            ok(f"{GITIGNORE}: no pattern conflicts with the index ({len(pats)} patterns)")

    if fails:
        print(f"dead-ref-check: {fails} violation(s)")
        return 1
    print("dead-ref-check: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
