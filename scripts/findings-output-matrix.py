#!/usr/bin/env python3
"""Pins the secretgate-action `findings` OUTPUT contract (C's c22 gap (a)).

The action publishes outputs.findings; until now NO caller ever asserted the
value, so a wiring regression (empty, non-integer, wrong count) would have
shipped silently. This harness extracts the action's Scan step run block
VERBATIM from the published action.yml (raw @ v1.2.2, the tag consumers use),
drives it with the real GITHUB_OUTPUT / GITHUB_STEP_SUMMARY / GITHUB_ACTION_PATH
env contract, and asserts BOTH verdict shapes:

  A1 clean fixture   -> GITHUB_OUTPUT carries exactly findings=0
  A2 dirty fixture   -> exactly findings=1  (fixture token assembled at
                        runtime; zero static tokens in this repo — c25
                        self-scan rule)
  A3 invalid scan in -> step exits 2 with error
  A4 fail=true dirty -> step exits 1 (gate actually gates)

Extraction is pinned to action.yml content asserts so a template refactor that
renames the step fails LOUD, not silently vacuous (c20/c21 assert-the-shape).
"""
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

ACTION_REF = "v1.2.2"
RAW = "https://raw.githubusercontent.com/tianzhicdev/secretgate-action/refs/tags/"

HERE = os.path.dirname(os.path.abspath(__file__))


def fetch(name):
    req = urllib.request.Request(
        RAW + ACTION_REF + "/" + name, headers={"Cache-Control": "no-cache"})
    return urllib.request.urlopen(req, timeout=30).read().decode()


def extract_scan_step(action_yml):
    # content asserts FIRST: a refactor of action.yml must break here, not
    # silently produce an empty (vacuously passing) extraction.
    assert "id: scan" in action_yml, "action.yml no longer has an id: scan step"
    assert "echo \"findings=$n\" >> \"$GITHUB_OUTPUT\"" in action_yml, \
        "action.yml no longer publishes findings via GITHUB_OUTPUT"
    m = re.search(
        r"id: scan\n(?:.*\n)*?      run: \|\n((?:        .*\n)+)", action_yml)
    assert m, "could not extract Scan step run block from action.yml"
    body = m.group(1)
    assert "findings=" in body and "GITHUB_OUTPUT" in body, \
        "extracted block lost the findings contract"
    return body


def run_step(body, tmp, scan, fail, sg, action_path, json_out, summary, out):
    env = dict(os.environ)
    env.update({
        "SG": sg, "SG_SCAN": scan, "SG_FAIL": fail,
        "SG_PATH": tmp, "SG_JSON_OUT": json_out,
        "GITHUB_STEP_SUMMARY": summary, "GITHUB_OUTPUT": out,
        "GITHUB_ACTION_PATH": action_path,
    })
    return subprocess.run(["bash", "-c", body], env=env,
                          capture_output=True, text=True, cwd=tmp)


def main():
    secretgate = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        HERE, "..", "secretgate.py")
    assert os.path.exists(secretgate), "secretgate.py not found: " + secretgate

    action_yml = fetch("action.yml")
    summarize = fetch("summarize.py")
    body = extract_scan_step(action_yml)

    results = []
    with tempfile.TemporaryDirectory() as tmp:
        action_path = os.path.join(tmp, "action")
        os.makedirs(action_path)
        with open(os.path.join(action_path, "summarize.py"), "w") as f:
            f.write(summarize)

        clean = os.path.join(tmp, "clean")
        dirty = os.path.join(tmp, "dirty")
        os.makedirs(clean)
        os.makedirs(dirty)
        with open(os.path.join(clean, "app.py"), "w") as f:
            f.write("print('hello world')\n")
        # runtime-assembled fixture token: no static AKIA string in this repo
        token = "AKIA" + "1234567890ABCDEF"
        with open(os.path.join(dirty, "conf.py"), "w") as f:
            f.write('aws_key = "%s"\n' % token)

        def drive(scan_dir, scan, fail):
            out = os.path.join(tmp, "gh_output_%s_%s" % (
                os.path.basename(scan_dir), fail))
            summary = out + ".summary"
            r = run_step(body, scan_dir, scan, fail, secretgate, action_path,
                         out + ".json", summary, out)
            published = ""
            if os.path.exists(out):
                pub = [l for l in open(out).read().splitlines()
                       if l.startswith("findings=")]
                assert len(pub) == 1, "expected exactly one findings line: %r" % pub
                published = pub[0].split("=", 1)[1]
            return r, published

        # A1 clean -> findings=0, exit 0
        r, n = drive(clean, "working", "true")
        results.append(("A1 clean publishes findings=0",
                        r.returncode == 0 and n == "0"))

        # A2 dirty, fail=false -> findings=1, exit 0 (report-only mode)
        r, n = drive(dirty, "working", "false")
        results.append(("A2 dirty publishes findings=1",
                        r.returncode == 0 and n == "1"))

        # A3 invalid scan input -> exit 2 before any scan
        r, n = drive(clean, "working; rm -rf /", "true")
        results.append(("A3 invalid scan input exits 2",
                        r.returncode == 2))

        # A4 dirty + fail=true -> exit 1 (the gate actually gates)
        r, n = drive(dirty, "working", "true")
        results.append(("A4 dirty+fail=true exits 1",
                        r.returncode == 1))

    ok = 0
    for name, passed in results:
        print(("PASS " if passed else "FAIL ") + name)
        ok += passed
    print("%d/%d" % (ok, len(results)))
    sys.exit(0 if ok == len(results) else 1)


if __name__ == "__main__":
    main()
