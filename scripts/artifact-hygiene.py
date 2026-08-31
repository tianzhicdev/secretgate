#!/usr/bin/env python3
"""Artifact-hygiene rail (A c50, C c40 shape adapted to this repo).

The accident class is fleet-born, not hypothetical: C's ethkey-lite silently
SHIPPED two CI byproducts (composite-run.sh + step.log) as tracked files for
15 commits on a public Pages URL — a local test run of a CI step staged its
scratch files (C c25/c40). The fix that pinned it forever reads `git ls-files`
(INDEX authority — a .gitignore entry never untracks what was committed
before it existed) instead of scanning the disk.

What THIS repo's CI writes inside the checkout (inventory @c50):
  - the py39-floor job redirects vermin stdout to `vermin.log` (secrets.yml
    'Floor claim machine-pinned' step).
  - the verify-release negative-controls job checks the verifier tool out to
    `.ethkey-tools/ethkey.py` in-tree (actions/checkout `path:`) —
    now pinned by leg D DERIVATION, no hand-listed literal.
  Nothing else: every matrix script (findings-output-matrix,
    scan-root-matrix) writes fixtures under tempfile.mkdtemp/mkdtemp
    OUTSIDE the checkout, and negative-controls fixtures are COMMITTED
    files under proofs/, never generated.
The rails this repo must never lose:

  A. BLOCKLIST: no generated-file name may ever be tracked again.
  B. SCRATCH SWEEP: no tracked *.log / *.out at any depth (the step.log
     class generalized by extension, so a NEW log name is caught even when
     nobody added it to leg A).
  D. CHECKOUT-PATH INVENTORY (A c54, C c44 offer): every job-level
     `actions/checkout` with a relative `path:` WRITES a whole directory
     into the checkout at CI time. The A c50 rail hand-listed
     `.ethkey-tools/ethkey.py`; leg D DERIVES the prefix set from the
     .github YAML text (stdlib line-scan, no PyYAML) so the NEXT `path:`
     step is covered without anyone editing a list, and the derived set is
     PRINTED (C c44 announce-yourself rule) so it can never derive vacuously.
  C. DOC DENOMINATOR: any tracked .md outside proofs/ must be named in
     DOC_ALLOW (README + SECURITY today). A new tracked .md that is neither
     a receipt nor an allowed doc goes RED — catches a RENAMED byproduct
     that bypassed the blocklist.
  E. BLOCKLIST<->IGNORE PARITY (A c55, B c44 offer): a blocklist entry that
     no .gitignore line covers is a CATCH WITH NO PREVENT — it stops the
     commit but never stops the staging, so every `git add -A` replays the
     accident. Authority is `git check-ignore --no-index` (B c43: ask git,
     don't reimplement fnmatch); a check-ignore crash is a crash, not a
     verdict: exit 2 WITH A NAME. Covers leg A names AND leg D's derived
     checkout prefixes (an unchecked-out checkout dir stages on
     `git add -A` — exactly C's c40 accident route). The OK line PRINTS
     the covered set (announce-yourself) so vacuous coverage is visible.

Exit codes: 0 clean, 1 a violation is printed, 2 bad usage / no git repo.
"""
import os
import subprocess
import sys

# Files the CI harness WRITES inside this checkout. They must never be
# tracked (git ls-files) -- present-in-worktree is by construction,
# present-in-git is an accident.
BLOCKLIST = frozenset({
    "vermin.log",                # py39-floor job: vermin stdout (secrets.yml)
})

# Tracked .md files outside proofs/ must be enumerated here (docs).
# A c56 (C c47 frozenset class, pair-back): a bare {...} is a SET only while
# NON-EMPTY — the cleanup that removes the LAST name makes it an empty DICT
# and the first `&` TypeErrors on the deletion commit. Declaration site
# pinned by harness F8 (empty stays GREEN, prints 0/N) + F8m (bare {} at
# empty must die naming TypeError). Membership-only uses (DOC_ALLOW `in`)
# mask the class silently, so both are declared frozenset().
DOC_ALLOW = frozenset({"README.md", "SECURITY.md"})


def tracked_files():
    r = subprocess.run(["git", "ls-files"], capture_output=True, text=True,
                       timeout=60)
    if r.returncode != 0:
        print("FAIL: git ls-files failed: " + r.stderr.strip())
        sys.exit(2)
    return r.stdout.split()


def checkout_paths():
    """D: derive the in-checkout `actions/checkout path:` prefixes from the
    workflow/action YAML TEXT (stdlib line-scan; PyYAML is NOT on the runner
    -- c21 lesson). A path: line counts only when it belongs to a checkout
    `with:` block: seen within 4 lines AFTER a `uses: actions/checkout`
    line, indented deeper than that uses: line. Returns a set of normalized
    relative prefixes; `${{`-templated or absolute paths are skipped from
    matching (can't resolve text) but printed as a NOTE so they can never
    hide silently."""
    prefixes, unresolvable = set(), []
    for root, dirs, files in os.walk(".github"):
        dirs[:] = [d for d in dirs if d != ".git"]
        for fn in files:
            if not fn.endswith((".yml", ".yaml")):
                continue
            p = os.path.join(root, fn)
            lines = open(p, encoding="utf-8", errors="replace").read().splitlines()
            for i, line in enumerate(lines):
                if "uses:" not in line or "actions/checkout@" not in line:
                    continue
                uses_indent = len(line) - len(line.lstrip())
                for nxt in lines[i + 1: i + 9]:
                    stripped = nxt.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    ind = len(nxt) - len(nxt.lstrip())
                    if stripped != "with:" and ind <= uses_indent:
                        break  # left the step's with: block
                    if ind > uses_indent and stripped.startswith("path:"):
                        val = stripped.split(":", 1)[1].strip().strip("'\"")
                        if "${{" in val:
                            unresolvable.append(f"{p}: {val}")
                        elif val.startswith("/") or val in (".", "./"):
                            unresolvable.append(f"{p}: {val} (absolute/self)")
                        else:
                            prefixes.add(val.rstrip("/") + "/")
                        break
                    if stripped.startswith(("- ", "uses:", "name:", "-name")):
                        break  # new step/entry, no path:
                    if ":" not in stripped:
                        break
    # action.yml at repo root (composite) can also carry checkout steps
    for extra in ("action.yml",):
        if os.path.isfile(extra):
            # composite actions run against the CALLER's checkout; a
            # path: here would be unusual. Scan with the same rule.
            lines = open(extra, encoding="utf-8", errors="replace").read().splitlines()
            for i, line in enumerate(lines):
                if "uses:" in line and "actions/checkout@" in line:
                    for nxt in lines[i + 1: i + 9]:
                        s = nxt.strip()
                        if s.startswith("path:"):
                            v = s.split(":", 1)[1].strip().strip("'\"")
                            if "${{" not in v and not v.startswith("/"):
                                prefixes.add(v.rstrip("/") + "/")
                            break
    for u in unresolvable:
        print(f"NOTE: checkout path not text-resolvable, leg D cannot match it: {u}")
    return prefixes
def main():
    if len(sys.argv) > 1:
        print(__doc__.strip().splitlines()[-1])
        return 2
    fails = 0
    files = tracked_files()

    # A. generated-file blocklist
    hits = sorted(set(files) & BLOCKLIST)
    for h in hits:
        print(f"FAIL: generated CI byproduct is tracked: {h}")
        fails += 1
    if not hits:
        print(f"OK: 0/{len(BLOCKLIST)} generated byproducts tracked")

    # B. scratch-name sweep: any tracked *.log / *.out at any depth
    scratch = sorted(f for f in files if f.endswith((".log", ".out")))
    for s in scratch:
        print(f"FAIL: tracked scratch log: {s}")
        fails += 1
    if not scratch:
        print("OK: no tracked *.log / *.out anywhere")

    # C. tracked .md outside proofs/ must be an allowed doc
    stray = sorted(
        f
        for f in files
        if f.endswith(".md")
        and not f.startswith("proofs/")
        and f not in DOC_ALLOW
    )
    for s in stray:
        print(f"FAIL: tracked .md outside proofs/ not in DOC_ALLOW: {s}")
        fails += 1
    if not stray:
        print("OK: tracked .md set == proofs/ receipts + DOC_ALLOW docs")

    # D. checkout-path inventory (derived, not hand-listed): any tracked
    # file under a job-level actions/checkout `path:` prefix is a tracked
    # clone byproduct. OK-line PRINTS the derived set (c38 announce-
    # yourself: a derived carve-out that prints nothing is a hole with a
    # name).
    prefixes = checkout_paths()
    dhits = sorted(f for f in files
                   if any(f.startswith(p) for p in prefixes))
    for h in dhits:
        print(f"FAIL: tracked file under a CI checkout path: {h}")
        fails += 1
    print(f"OK: checkout-path legs derived {sorted(prefixes)}"
          if not dhits else
          f"checkout-path prefixes scanned: {sorted(prefixes)}")

    # E. blocklist<->ignore parity (A c55, B c44 offer): catch AND prevent.
    # Leg A names + leg D derived prefixes must each score rc=0 under
    # `git check-ignore --no-index` (git is the matcher; do not reimplement
    # it, B c43). rc=1 = catch-without-prevent: the rail would name the
    # byproduct only AFTER an accident staged it. rc>1 = git itself
    # crashed: exit 2 WITH A NAME (B c43 rule — a crash must not score
    # like a verdict).
    prevent = sorted(set(BLOCKLIST) | set(prefixes))
    uncovered = []
    for name in prevent:
        # a derived prefix is a directory ('x/'); a dir-only ignore pattern
        # never matches the bare dir name under check-ignore, so probe a
        # child path — the exact shape `git add -A` would stage.
        probe = name + ".c55-probe" if name.endswith("/") else name
        pr = subprocess.run(["git", "check-ignore", "--no-index", "-q", probe],
                            capture_output=True, text=True, timeout=60)
        if pr.returncode == 1:
            uncovered.append(probe)
        elif pr.returncode > 1:
            print(f"FAIL: git check-ignore on {probe} errored rc="
                  f"{pr.returncode}: {pr.stderr.strip()} (authority broken, "
                  "not a verdict)")
            sys.exit(2)
    for u in uncovered:
        print(f"FAIL: blocklist/checkout name with NO ignore line "
              f"(catch-without-prevent, B c44 class): {u}")
        fails += 1
    if not uncovered:
        # N/N denominator (B c46 delta): the covered count is printed AS A
        # NUMBER, not just as a set to eyeball — a mutant that shrinks the
        # union (e.g. leg-D derivation breaking) moves the printed count,
        # so the assertable quantity exists without regex-over-set work.
        # B's shape 'N/N catch+prevent names ignored'; tail kept verbatim
        # so c57's printed_covered parser rides the same line unchanged.
        n = len(prevent)
        print(f"OK: {n}/{n} catch+prevent — every leg-A/leg-D name is ignored: {prevent}")

    if fails:
        print(f"artifact-hygiene: {fails} violation(s)")
        return 1
    print("artifact-hygiene: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
