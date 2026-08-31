#!/usr/bin/env python3
"""c124 fs-blindness matrix — the teeth behind audit_blind (EXPECT.md E0-E7
+ P1/P2). Runs the shipped engine over fixture worlds; chmods restored in
finally (never leave a 000 world behind). Self-cleans its fixture world
(C c116 law: fabricated exhibits must not pollute real scans).

Every cell asserts rc AND output shape (stdout 'clean' vs stderr 'blind:'),
zero-traceback assert on the rc-2 legs (B c107 crash-wears-verdict class).
P1 flip: audit_blind call REMOVED from a /tmp copy reproduces the D0
rc=0 CLEAN escape = the audit is the tooth, not decoration.
P2 control: shipped tool on honest clean fixture == rc 0 (non-vacuous).
"""
import os
import shutil
import subprocess
import sys
import tempfile

ENGINE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..",
                                      "..", "secretgate", "secretgate.py"))
PLANT = "AKIA" + "ABCDEFGHIJKLMNOP"  # runtime-assembled: no static token (c25 law)
fails = 0
total = 0


def run(engine, path):
    r = subprocess.run([sys.executable, engine, "scan", path],
                       capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout, r.stderr


def cell(name, engine, path, want_rc, want_in_stdout=None, want_in_stderr=None,
         ban_traceback=True):
    global fails, total
    total += 1
    rc, out, err = run(engine, path)
    ok = rc == want_rc
    if want_in_stdout and want_in_stdout not in out:
        ok = False
    if want_in_stderr and want_in_stderr not in err:
        ok = False
    if ban_traceback and "Traceback" in err:
        ok = False
    print(("PASS " if ok else "FAIL ") + name +
          f" (rc={rc} out={out[:40]!r} err={err[:80]!r})")
    if not ok:
        fails += 1


def gitc(repo, *a):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a],
                   cwd=repo, check=True, capture_output=True)


def main():
    global fails
    # Root sees mode-000 as readable: every blindness cell would go green
    # with the doors never engaged = vacuous teeth (c103 fail-closed law).
    # Hosted CI runs as 'runner' (non-root, proven in runner logs); a
    # root-driven run must OPT IN explicitly, never silently pass.
    if hasattr(os, "geteuid") and os.geteuid() == 0 \
            and os.environ.get("FS_BLIND_ALLOW_ROOT") != "1":
        print("fs-blind matrix: REFUSING to run as root (000 doors don't "
              "bind; set FS_BLIND_ALLOW_ROOT=1 only if you know why)",
              file=sys.stderr)
        sys.exit(2)
    tmp = tempfile.mkdtemp(prefix="c124fs-")
    saved = []
    try:
        # E0/P2 honest clean repo
        clean = os.path.join(tmp, "clean")
        os.makedirs(clean)
        open(os.path.join(clean, "ok.txt"), "w").write("nothing here\n")
        gitc(clean, "init", "-q")
        gitc(clean, "add", "ok.txt")
        gitc(clean, "commit", "-qm", "i")
        cell("E0/P2 honest clean repo", ENGINE, clean, 0, want_in_stdout="clean")

        # E1 out-of-repo dir tree, plant inside mode-000 subdir
        d1 = os.path.join(tmp, "d1", "sub")
        os.makedirs(d1)
        open(os.path.join(tmp, "d1", "a.txt"), "w").write("ok\n")
        open(os.path.join(d1, "plant.txt"), "w").write(PLANT)
        os.chmod(d1, 0)
        saved.append(d1)
        cell("E1 000 subdir (pre-fix FALSE CLEAN D0)", ENGINE,
             os.path.join(tmp, "d1"), 2, want_in_stderr="blind:")

        # E2 git repo, mode-000 UNTRACKED plant
        g2 = os.path.join(tmp, "g2")
        os.makedirs(g2)
        open(os.path.join(g2, "ok.txt"), "w").write("ok\n")
        gitc(g2, "init", "-q")
        gitc(g2, "add", "ok.txt")
        gitc(g2, "commit", "-qm", "i")
        f2 = os.path.join(g2, "plant.txt")
        open(f2, "w").write(PLANT)
        os.chmod(f2, 0)
        saved.append(f2)
        cell("E2 000 untracked file (pre-fix D1)", ENGINE, g2, 2,
             want_in_stderr="blind:")

        # E3 git repo, mode-000 TRACKED plant (rebuilt from g2's shape:
        # copytree CANNOT read a 000 file — restore g2 first, self-lesson:
        # the fixture builder itself hit the class under test)
        os.chmod(f2, 0o644)
        g3 = os.path.join(tmp, "g3")
        shutil.copytree(g2, g3)
        os.chmod(os.path.join(g3, "plant.txt"), 0o644)
        gitc(g3, "add", "plant.txt")
        gitc(g3, "commit", "-qm", "plant")
        os.chmod(os.path.join(g3, "plant.txt"), 0)
        saved.append(os.path.join(g3, "plant.txt"))
        cell("E3 000 tracked file (pre-fix D2)", ENGINE, g3, 2,
             want_in_stderr="blind:")

        # E4 blind file the walk-mode SKIP rule exempts (.pyc) -> explicit
        # verdict. OUT-of-repo (walk mode): git mode yields .pyc to the scan
        # by pre-existing design (binary NUL-skip), so a 000 .pyc IN a repo
        # is a scan target = blindness rc 2, measured as a bonus cell below.
        d4 = os.path.join(tmp, "d4")
        os.makedirs(d4)
        open(os.path.join(d4, "ok.txt"), "w").write("ok\n")
        f4 = os.path.join(d4, "cache.pyc")
        open(f4, "w").write(PLANT)
        os.chmod(f4, 0)
        saved.append(f4)
        cell("E4 000 .pyc exempt by walk SKIP rule (no repo)", ENGINE, d4, 0,
             want_in_stdout="clean")
        g4b = os.path.join(tmp, "g4b")
        os.makedirs(g4b)
        open(os.path.join(g4b, "ok.txt"), "w").write("ok\n")
        gitc(g4b, "init", "-q")
        gitc(g4b, "add", "ok.txt")
        gitc(g4b, "commit", "-qm", "i")
        f4b = os.path.join(g4b, "cache.pyc")
        open(f4b, "w").write(PLANT)
        os.chmod(f4b, 0)
        saved.append(f4b)
        cell("E4b 000 .pyc IN git repo = scan target = blind rc 2",
             ENGINE, g4b, 2, want_in_stderr="blind:")

        # E5 blind file named in .secretgateignore -> explicit verdict
        g5 = os.path.join(tmp, "g5")
        os.makedirs(g5)
        open(os.path.join(g5, "ok.txt"), "w").write("ok\n")
        open(os.path.join(g5, ".secretgateignore"), "w").write("fixtures/\n")
        gitc(g5, "init", "-q")
        gitc(g5, "add", ".")
        gitc(g5, "commit", "-qm", "i")
        sub5 = os.path.join(g5, "fixtures")
        os.makedirs(sub5)
        os.chmod(sub5, 0)
        saved.append(sub5)
        cell("E5 000 dir inside .secretgateignore (dir-form match)",
             ENGINE, g5, 0, want_in_stdout="clean")

        # E6 nonexistent path (pre-existing leg unchanged)
        cell("E6 nonexistent path", ENGINE, os.path.join(tmp, "nope"), 2,
             want_in_stderr="does not exist")

        # E7 mode-000 dir INSIDE a git repo (git can't enumerate its contents)
        g7 = os.path.join(tmp, "g7")
        os.makedirs(g7)
        open(os.path.join(g7, "ok.txt"), "w").write("ok\n")
        gitc(g7, "init", "-q")
        gitc(g7, "add", "ok.txt")
        gitc(g7, "commit", "-qm", "i")
        d7 = os.path.join(g7, "secret")
        os.makedirs(d7)
        open(os.path.join(d7, "plant.txt"), "w").write(PLANT)
        os.chmod(d7, 0)
        saved.append(d7)
        cell("E7 000 dir inside git repo", ENGINE, g7, 2,
             want_in_stderr="blind:")

        # P1 FLIP: remove the audit call from a /tmp copy -> E1 escapes CLEAN
        flip = os.path.join(tmp, "flipgate.py")
        src = open(ENGINE, encoding="utf-8").read()
        needle = "        audit_blind(root, ignore_pats)\n"
        # remove the CALL, keep the block legal: mutate the entry, not the
        # syntax (C c116 flip-battery law: mutate the gate, keep the body).
        if src.count(needle) != 1:
            print(f"FAIL P1 setup: audit call found {src.count(needle)}x, "
                  "expected exactly 1")
            fails += 1
        else:
            open(flip, "w", encoding="utf-8").write(
                src.replace(needle, "        pass  # P1: audit removed\n"))
            import py_compile
            py_compile.compile(flip, doraise=True)  # c121: mutants must compile
            cell("P1 FLIP audit-removed, E1-shape ESCAPES CLEAN rc 0",
                 flip, os.path.join(tmp, "d1"), 0, want_in_stdout="clean",
                 ban_traceback=False)
    finally:
        for p in saved:
            try:
                os.chmod(p, 0o755 if os.path.isdir(p) else 0o644)
            except OSError:
                pass
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"fs-blind matrix: {total - fails}/{total}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
