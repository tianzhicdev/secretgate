#!/usr/bin/env python3
"""A c24: behavioral proof that secretgate allow-annotations are SAME-LINE ONLY.
Run from a dir containing the shipped secretgate.py. 10 asserts, exit != 0 on
any FAIL (drop this in CI if the rule ever needs pinning in a repo)."""
import importlib.util
import os
import pathlib
import sys

# importlib-by-path, not plain import: a module import resolves from the
# SCRIPT's dir, not CWD (C's c20 ESM pitfall in python form). Point at the
# shipped tool: $SECRETGATE env, else repo-root secretgate.py (CI layout),
# else the evidence-dir mirror (agents/A/work layout); spec assert so a wrong
# path fails loudly at boot, not as a phantom test failure.
_here = pathlib.Path(__file__).resolve().parent
_candidates = [
    os.environ.get("SECRETGATE", ""),
    str(_here.parent / "secretgate.py"),
    str(_here.parents[1] / "secretgate" / "secretgate.py"),
]
src = next((c for c in _candidates if c and pathlib.Path(c).is_file()), "")
spec = importlib.util.spec_from_file_location("secretgate", src) if src else None
assert spec and spec.loader, f"cannot load secretgate from any of {_candidates}"
secretgate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(secretgate)

# Assembled at runtime so NO static AKIA+16 token exists in this file —
# otherwise the matrix fixture trips secretgate when it scans its own repo.
FLAG = 'API_KEY = "' + "AKIA" + "1234567890ABCDEF" + '"'
cases = [
    ("plain flag", FLAG, True),
    ("allow on NEXT line = no-op", FLAG + "\n# secretgate: allow", True),
    ("allow on PRECEDING line = no-op", "# secretgate: allow\n" + FLAG, True),
    ("allow html-comment AFTER = no-op", FLAG + "\n<!-- secretgate: allow -->", True),
    ("same-line # allow", FLAG + "  # secretgate: allow", False),
    ("same-line // allow", FLAG + "  // secretgate: allow", False),
    ("same-line html-comment allow", FLAG + "  <!-- secretgate: allow pub -->", False),
    ("same-line nosec", FLAG + "  # nosec", False),
    ("same-line pragma allowlist", FLAG + "  # pragma: allowlist", False),
    ("same-line do not flag", FLAG + "  # do not flag", False),
]

fails = 0
for name, text, expect_flagged in cases:
    flagged = len(secretgate.scan_text(text, "x.py")) > 0
    ok = flagged == expect_flagged
    fails += not ok
    print(("PASS" if ok else "FAIL"), "|", name, "| flagged =", flagged)
print("MATRIX:", len(cases) - fails, "/", len(cases))
sys.exit(1 if fails else 0)
