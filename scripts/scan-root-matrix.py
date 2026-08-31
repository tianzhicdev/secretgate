#!/usr/bin/env python3
"""Pins the scan-root contract: `secretgate scan PATH` must scan PATH, not
silently scan nothing (C's c31 defect report, fixed in engine v1.2.2).

Defect class: files_working_tree() enumerated via `git ls-files` (names are
REPO-TOP-relative) and joined them onto the scan root. With root=subdir every
candidate path was doubled (sub/sub/x) and silently isfile()-skipped — so
`scan sub` inside a git repo reported a FALSE CLEAN (exit 0) for ANY file,
tracked or untracked, while `scan .` found the same plants. A clean verdict
from a scan that scanned nothing is the worst output a secret scanner can
produce; the action's `path` input invites exactly this usage.

The matrix builds a throwaway git repo per run and plants tokens ASSEMBLED AT
RUNTIME (c25 self-scan rule: zero static real-format tokens in this repo):

  M1 scan .      dirty repo top       -> rc 1, findings name both plants
  M2 scan sub    UNTRACKED plant      -> rc 1   (old engine: rc 0 FALSE CLEAN)
  M3 scan sub    TRACKED plant        -> rc 1   (old engine: rc 0 FALSE CLEAN)
  M4 scan sub    clean subdir         -> rc 0   (non-vacuity: the matrix can
                                                 go green; it is not rc!=0 love)
  M5 scan sub    deep nested plant    -> rc 1   (path join is recursive-correct)
  M6 scan DIR    outside any repo     -> rc 1   (os.walk fallback still works)
  M7 scan sub    plant + allow comment on SAME line -> rc 0 (allow rule still
                                       applies through the new -C route)

Runs the engine via $SECRETGATE (CI sets it to the repo's own secretgate.py);
falling back to the repo root. Exits 1 naming any failed case.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ENGINE = os.environ.get("SECRETGATE") or os.path.join(ROOT, "secretgate.py")
assert os.path.isfile(ENGINE), f"engine not found: {ENGINE}"

# runtime-assembled token: regexes scan source text, not values (c25 rule)
AKIA = "AKIA" + "1234567890ABCDEF"


def git(repo, *args):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    *args], cwd=repo, check=True, capture_output=True)


def make_repo(tmp):
    os.makedirs(os.path.join(tmp, "sub"), exist_ok=True)
    git(tmp, "init", "-q")
    with open(os.path.join(tmp, "README.md"), "w") as f:
        f.write("clean file\n")
    git(tmp, "add", "README.md")
    git(tmp, "commit", "-qm", "init")
    return tmp


def plant(tmp, rel, allow=False):
    p = os.path.join(tmp, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        tail = "  # secretgate: allow test fixture token" if allow else ""
        f.write(f'key = "{AKIA}"{tail}\n')
    return p


def run(tmp, *args):
    r = subprocess.run([sys.executable, ENGINE, "scan", *args],
                       cwd=tmp, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


CASES = []


def case(name):
    def deco(fn):
        CASES.append((name, fn))
        return fn
    return deco


@case("M1 scan . dirty repo top finds plants in subdir")
def m1(tmp):
    plant(tmp, "sub/plant.py")
    rc, out = run(tmp, ".")
    assert rc == 1, f"expected rc1 got {rc}: {out}"
    assert "sub/plant.py" in out, out


@case("M2 scan sub finds UNTRACKED plant (c31 defect)")
def m2(tmp):
    plant(tmp, "sub/plant.py")
    rc, out = run(tmp, "sub")
    assert rc == 1, f"FALSE CLEAN (old-engine class): rc={rc} out={out}"
    assert "plant.py" in out, out


@case("M3 scan sub finds TRACKED plant (c31 defect)")
def m3(tmp):
    plant(tmp, "sub/plant.py")
    git(tmp, "add", "-f", "sub/plant.py")
    git(tmp, "commit", "-qm", "plant")
    rc, out = run(tmp, "sub")
    assert rc == 1, f"FALSE CLEAN on tracked file: rc={rc} out={out}"


@case("M4 scan sub clean subdir stays green (non-vacuity)")
def m4(tmp):
    with open(os.path.join(tmp, "sub", "clean.txt"), "w") as f:
        f.write("nothing to see\n")
    rc, out = run(tmp, "sub")
    assert rc == 0, f"clean subdir must be rc0: {out}"


@case("M5 scan sub/deeper deep plant found")
def m5(tmp):
    plant(tmp, "sub/deeper/nest.py")
    rc, out = run(tmp, "sub/deeper")
    assert rc == 1, f"deep scan rc={rc}: {out}"


@case("M6 scan DIR outside a repo (walk fallback)")
def m6(tmp):
    outside = tempfile.mkdtemp(prefix="sg-outside-")
    plant(outside, "a.py")
    r = subprocess.run([sys.executable, ENGINE, "scan", outside],
                       capture_output=True, text=True)
    assert r.returncode == 1, f"walk fallback rc={r.returncode}: {r.stdout}"


@case("M7 same-line allow comment clears through -C route")
def m7(tmp):
    plant(tmp, "sub/allowed.py", allow=True)
    rc, out = run(tmp, "sub")
    assert rc == 0, f"allow-comment regression via new route: rc={rc} {out}"


def main() -> int:
    bad = 0
    for name, fn in CASES:
        tmp = tempfile.mkdtemp(prefix="sg-root-")
        try:
            fn(make_repo(tmp))
            print(f"ok: {name}")
        except AssertionError as e:
            print(f"FAIL: {name} — {e}", file=sys.stderr)
            bad += 1
    if bad:
        print(f"scan-root matrix: {bad}/{len(CASES)} FAILED", file=sys.stderr)
        return 1
    print(f"scan-root matrix: {len(CASES)}/{len(CASES)} ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
