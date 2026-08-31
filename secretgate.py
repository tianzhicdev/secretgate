#!/usr/bin/env python3
"""secretgate - a zero-dependency secret scanner for git repos.

Scans the working tree, the index, or full git history for leaked credentials
(API keys, tokens, private keys, high-entropy strings). Designed to run as a
pre-commit / pre-push hook. Stdlib only, Python 3.9+.

Usage:
  secretgate scan [PATH]              scan tracked+untracked files (default .);
                                      PATH may also be a single FILE (v1.2.3)
  secretgate scan --staged            scan staged diff only (pre-commit use)
  secretgate scan --history           scan every blob in all git history
  secretgate install                  install as pre-commit hook in this repo
  secretgate rules                    list built-in detection rules

Ignore files:
  Lines in .secretgateignore (repo root; gitignore-style globs, # comments)
  exclude paths from scanning. Use for intentionally-entropic files like
  checked-in signed receipts or fixtures, e.g.:
      proofs/
      tests/fixtures/*.b64

Exit code 1 if findings, 0 otherwise. Use --fail-on-none to always exit 0.
"""

from __future__ import annotations

import argparse
import math
import os
import re
import subprocess
import sys
from collections import namedtuple

Finding = namedtuple("Finding", "path line rule secret_preview severity")

# (name, regex, severity). Regexes capture the secret in group "secret".
RULES = [
    ("aws-access-key", re.compile(r"(?P<secret>AKIA[0-9A-Z]{16})"), "high"),
    ("github-token", re.compile(r"(?P<secret>gh[pousr]_[A-Za-z0-9]{36,})"), "high"),
    ("github-fine-grained", re.compile(r"(?P<secret>github_pat_[A-Za-z0-9_]{22,})"), "high"),
    ("openai-key", re.compile(r"(?P<secret>sk-[A-Za-z0-9_-]{20,})"), "high"),
    ("slack-token", re.compile(r"(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,})"), "high"),
    ("stripe-key", re.compile(r"(?P<secret>(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,})"), "high"),
    ("private-key-block", re.compile(r"(?P<secret>-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----)"), "high"),
    ("slack-webhook", re.compile(r"(?P<secret>https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"), "high"),
    ("google-api-key", re.compile(r"(?P<secret>AIza[0-9A-Za-z_-]{35})"), "high"),
    ("huggingface-token", re.compile(r"(?P<secret>hf_[A-Za-z]{34,})"), "high"),
    ("anthropic-key", re.compile(r"(?P<secret>sk-ant-[A-Za-z0-9_-]{20,})"), "high"),
    ("twilio-key", re.compile(r"(?P<secret>AC[a-f0-9]{32})"), "medium"),
    ("npm-token", re.compile(r"(?P<secret>npm_[A-Za-z0-9]{36})"), "high"),
    ("generic-api-key", re.compile(r"(?i)(?:api[_-]?key|apikey|secret|token|passwd|password)\s*[:=]\s*['\"]?(?P<secret>[^\s'\"]{16,})['\"]?"), "medium"),
    ("bearer-jwt", re.compile(r"(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})"), "medium"),
    ("connection-string", re.compile(r"(?P<secret>(?:postgres|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@[^\s/]+)"), "high"),
]

# Words that commonly false-positive as generic keys; skip generic-api-key
# matches whose secret is one of these or looks like a placeholder/template.
# v1.2.1 suppression fix (c34 mutation probe): the old bare `xxx+` matched a
# 3-char x-run ANYWHERE, so ~0.11% of genuinely random secrets (any 40-char
# base64 token containing a literal "xxx") were silently dropped. Masking
# intent is a run that either stands alone as its own word (xxxxxxx, sk-xxx-)
# or is long (>=5) as in AKIAxxxxx / sk_live_XXXX...; random-token mid-runs
# are 3-4 chars and now survive to be flagged.
# v1.2.4 dictionary-arm fix (c85 sweep): the dictionary arms (changeme|your|
# placeholder|example|dummy|test[-_]|redacted|insert) were RAW unanchored
# substrings — the exact sibling of the 'xxx+' arm fixed in v1.2.1 and the
# 'nosec' arm in ALLOW_COMMENT_RE. Measured (agents/A/work/c85-placeholder-
# substr/): a 40-hex secret with a literal 'insert'/'example'/'your'/'xxx'
# embedded ANYWHERE is silently dropped on BOTH the generic-api-key path and
# the entropy-sweep path — rc 0 false clean at every published gen v1.1.0..
# v1.2.3, entropy leg machine-proven non-vacuous (token scores + no other
# placeholder match with the word removed; only the word delta suppresses).
# Word-boundary lookbehind anchors the arms to a token START: template
# dialects (insert-key-here, changeme123, YOUR_TOKEN, your_api_key_here) stay
# suppressed; mid-token embeddings survive to be flagged. Blast radius on
# fleet bytes: 0 delta (931+416 findings identical old-vs-new).
# v1.2.5 x5-arm fix (C c81 x5_midrun + A c86 probe): the bare `x{5,}` arm —
# kept by the v1.2.1 rationale 'masking intent ... or long (>=5)' — sat
# OUTSIDE the c85 lookbehind: a real secret with any literal 5-x run
# mid-value was blessed on both paths at every gen incl v1.2.4
# (agents/A/work/c86-x5-donotflag/ 22-cell matrix). The rationale's own
# examples are self-refuting: AKIA+16x is flagged by the exact vendor rule
# (no placeholder logic there — measured kill both gens), and a long run
# after a word char is an EMBED, not a mask. Masking intent needs the run to
# STAND ALONE (anchored arm covers any length incl 'XXXX...XXXX',
# 'sk_live_xxx', '<your-key>'); an alphanumeric-preceded tail run is the
# embed shape. Bare arm dropped = last unanchored substring in the file.
# RESIDUAL CONTRACT (measured, c86): the trailing shape `x{5,}(?![A-Za-z0-9])`
# stays suppressed — lowercase masked fixtures ('AKIA' + 16 lowercase x, the
# A2 vocab-pin) never reach the uppercase-only vendor rule, and a
# word-char-preceded MID-value run (embed) now survives. Mid = kill,
# tail = mask: the discriminator is the lookahead, not the length.
# v1.2.5 prose-arm fix (C c80/c81 do_not_flag): 'do\s+not\s+flag' word-
# bounded (trailing \b — the old form matched inside 'flaggable'); kept as a
# DOCUMENTED opt-in, same standing as \bnosec\b (README allow-comment section,
# index.html, action README all name it). C's 'undocumented' charge measured
# FALSE on README/index surfaces (grep-confirmed c86); the unbounded-tail
# charge was real and is now closed.
PLACEHOLDER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(changeme|your[-_]?|placeholder|example|dummy|test(ing)?[-_]|redacted|insert)|(?<![A-Za-z0-9])x{3,}(?![A-Za-z0-9])|x{5,}(?![A-Za-z0-9])|<.*>|\{\{.*\}\}|\$\{.*\}"
)
SKIP_FILE_RE = re.compile(
    r"(?i)(^|/)(\.git/|node_modules/|dist/|build/|venv/|\.venv/|__pycache__/|target/|vendor/)|\.(lock|min\.js|min\.css|map|png|jpg|jpeg|gif|ico|woff2?|ttf|eot|pdf|zip|gz|bz2|xz|so|dll|dylib|class|pyc|wasm)$"
)
# v1.2.1: `nosec` was an unanchored substring — any line merely containing
# "nosecret..." (a variable name, a sentence) silenced EVERY finding on it.
# Word-bounded: opt-in stays `nosec` / `secretgate: allow`, never a substring.
ALLOW_COMMENT_RE = re.compile(r"(?i)secretgate:?\s*allow|\bnosec\b|pragma:\s*allowlist|\bdo\s+not\s+flag\b")

IGNORE_FILE_NAME = ".secretgateignore"


def load_ignore_patterns(root: str = ".") -> list[str]:
    """Read .secretgateignore at repo/root dir. Blank lines and # comments ignored."""
    path = os.path.join(root, IGNORE_FILE_NAME)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return [ln.strip() for ln in fh
                    if ln.strip() and not ln.strip().startswith("#")]
    except OSError:
        return []


def is_ignored(rel_path: str, patterns: list[str]) -> bool:
    """gitignore-flavoured match: 'dir/' prefixes, '*' globs via fnmatch,
    bare names match any path segment or a file's basename."""
    from fnmatch import fnmatch
    parts = rel_path.split("/")
    for pat in patterns:
        if pat.endswith("/"):
            d = pat.rstrip("/")
            if any(fnmatch(p, d) for p in parts[:-1]):
                return True
        elif "*" in pat or "?" in pat:
            if fnmatch(rel_path, pat) or any(fnmatch(p, pat) for p in parts):
                return True
        else:
            if rel_path == pat or parts[-1] == pat or pat in parts:
                return True
    return False


def _ignore_root(root: str = ".") -> str:
    """Where to look for .secretgateignore: repo top-level if in a git repo."""
    # v1.2.3: a FILE arg — dirname FIRST, else `git -C <file>` raises here too
    # (same raise-shape as the c69 defect, one function down) and the ignore
    # file silently never loads: `scan proofs/x-proof.md` printed 168 findings
    # that dir mode correctly ignores. Measured, then pinned (matrix M13).
    if os.path.isfile(root):
        root = os.path.dirname(root) or "."
    try:
        top = git("-C", root, "rev-parse", "--show-toplevel").strip()
        if top:
            return top
    except Exception:
        pass
    return root

ENTROPY_MIN_LEN = 24
ENTROPY_THRESHOLD = 4.35  # bits/char; ~random base64/hex tokens exceed this


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def preview(secret: str) -> str:
    if len(secret) <= 10:
        return secret[:2] + "***"
    return f"{secret[:4]}…{secret[-3:]} ({len(secret)} chars)"


def score_token(tok: str) -> bool:
    """True if a bare token looks like a credential by entropy + charset."""
    if len(tok) < ENTROPY_MIN_LEN or len(tok) > 128:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/_=-]{%d,128}" % ENTROPY_MIN_LEN, tok):
        return False
    return shannon_entropy(tok) >= ENTROPY_THRESHOLD


def scan_text(text: str, path: str) -> list[Finding]:
    out: list[Finding] = []
    seen = set()
    raw_matched_by_line: dict[int, list[str]] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        if ALLOW_COMMENT_RE.search(line):
            continue
        for rule, rx, sev in RULES:
            for m in rx.finditer(line):
                secret = m.group("secret")
                if rule == "generic-api-key" and (PLACEHOLDER_RE.search(secret) or not score_token(secret) and len(secret) < 20):
                    continue
                key = (path, lineno, rule, secret)
                if key in seen:
                    continue
                seen.add(key)
                raw_matched_by_line.setdefault(lineno, []).append(secret)
                out.append(Finding(path, lineno, rule, preview(secret), sev))
        # entropy sweep on long tokens
        for m in re.finditer(r"[A-Za-z0-9+/_=-]{24,128}", line):
            tok = m.group(0)
            if not score_token(tok) or PLACEHOLDER_RE.search(tok):
                continue
            # skip if this exact token (or one containing it) already flagged here
            if any(tok in raw or raw in tok for raw in raw_matched_by_line.get(lineno, ())):
                continue
            key = (path, lineno, "high-entropy", tok)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(path, lineno, "high-entropy", preview(tok), "low"))
    return out


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def _top_relative_prefix(root: str) -> str:
    """'sub/deeper/' when root sits that far below the repo top ('' at top
    or outside a repo): ls-files -C root gives names relative to the SCAN
    ROOT, but .secretgateignore patterns are matched repo-top-relative (the
    file loads from _ignore_root), so the two frames must agree before
    is_ignored() sees them (v1.2.3 false-RED class)."""
    try:
        top = git("-C", root, "rev-parse", "--show-toplevel").strip()
        rabs = os.path.abspath(root)
        if top and rabs != top and rabs.startswith(top + os.sep):
            return os.path.relpath(rabs, top).replace(os.sep, "/") + "/"
    except Exception:
        pass
    return ""


def files_working_tree(root: str):
    if os.path.isfile(root):
        # v1.2.3 (C c69 defect #2): a FILE arg previously fell into both
        # branches and yielded ZERO files — in-repo: `git -C <file>` raises
        # -> names=[]; out-of-repo: os.walk on a file yields nothing — so
        # `scan <file>` printed a FALSE CLEAN (rc 0) for ANY file, plants
        # included. An explicitly-named file is the whole scan: yield it.
        # Ignore-file semantics stay path-based (consistent with dir mode);
        # same-line allow comments still apply via scan_text.
        yield root, root
        return
    if os.path.isdir(os.path.join(root, ".git")) or _inside_repo(root):
        try:
            # -C root: names come back relative to the SCAN ROOT, not the repo
            # top. Without it, `scan sub` in a git repo joined root-relative
            # names onto the subdir root (sub/sub/x), isfile() skipped every
            # candidate, and the scan reported a FALSE CLEAN for any file —
            # tracked or not (C c31 defect report; pinned by
            # scripts/scan-root-matrix.py).
            tracked = git("-C", root, "ls-files").splitlines()
            untracked = git("-C", root, "ls-files", "--others", "--exclude-standard").splitlines()
            names = tracked + untracked
        except subprocess.CalledProcessError:
            names = []
        # v1.2.3: .secretgateignore patterns are REPO-TOP-relative, but -C
        # made the names above scan-root-relative — `scan sub` with 'sub/' in
        # the ignore file false-RED'd every ignored file (over-broad inverse
        # of the c69 class; measured: scan proofs/ printed 1098 findings dir
        # mode ignores). Prefix names back to top-relative for the MATCH
        # only; the isfile join stays scan-root-relative (the c31 fix).
        ignore_prefix = _top_relative_prefix(root)
        for n in names:
            p = os.path.join(root, n) if root != "." else n
            if os.path.isfile(p):
                yield (ignore_prefix + n if ignore_prefix else n), p
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not SKIP_FILE_RE.search(os.path.join(dirpath, d) + "/")]
            for f in filenames:
                p = os.path.join(dirpath, f)
                if not SKIP_FILE_RE.search(p):
                    yield p, p


def _inside_repo(root: str) -> bool:
    try:
        return git("-C", root, "rev-parse", "--is-inside-work-tree").strip() == "true"
    except Exception:
        return False


def read_text(p: str) -> str | None:
    try:
        if os.path.getsize(p) > 2 * 1024 * 1024:
            return None
        with open(p, "rb") as fh:
            data = fh.read()
        if b"\x00" in data[:8000]:
            return None
        return data.decode("utf-8", errors="replace")
    except OSError:
        return None


def scan_working_tree(root: str) -> list[Finding]:
    findings = []
    ignore_pats = load_ignore_patterns(_ignore_root(root))
    for name, p in files_working_tree(root):
        if is_ignored(name, ignore_pats):
            continue
        text = read_text(p)
        if text is None:
            continue
        findings.extend(scan_text(text, name))
    return findings


def scan_staged() -> list[Finding]:
    findings = []
    ignore_pats = load_ignore_patterns(_ignore_root())
    diff = git("diff", "--cached", "--unified=0")
    cur = None
    lineno = 0
    for dline in diff.splitlines():
        if line_is_new_file(dline):
            cur = dline[6:]
        elif dline.startswith("@@"):
            m = re.search(r"\+(\d+)", dline)
            lineno = int(m.group(1)) if m else 0
        elif dline.startswith("+") and not dline.startswith("+++"):
            if cur and not SKIP_FILE_RE.search(cur) and not is_ignored(cur, ignore_pats):
                for f in scan_text(dline[1:], cur):
                    findings.append(f._replace(line=lineno))
            lineno += 1
    return findings


def line_is_new_file(dline: str) -> bool:
    return dline.startswith("+++ b/")


def scan_history() -> list[Finding]:
    # NOTE: history scan is deliberately ignore-file-free: a blob's path in a
    # past commit is not its path today, so honoring .secretgateignore here
    # could hide genuinely-leaked history. Keep --history strict.
    findings = []
    revs = git("rev-list", "--all").split()
    seen_blobs = set()
    for rev in revs:
        try:
            listing = git("ls-tree", "-r", rev)
        except subprocess.CalledProcessError:
            continue
        for entry in listing.splitlines():
            meta, rest = entry.split("\t", 1)
            mode, typ, sha = meta.split()
            if typ != "blob" or sha in seen_blobs:
                continue
            seen_blobs.add(sha)
            path = rest
            if SKIP_FILE_RE.search(path):
                continue
            try:
                blob = subprocess.run(["git", "cat-file", "blob", sha], capture_output=True, check=True).stdout
            except subprocess.CalledProcessError:
                continue
            if b"\x00" in blob[:8000] or len(blob) > 2 * 1024 * 1024:
                continue
            f = scan_text(blob.decode("utf-8", errors="replace"), f"{path}@{rev[:8]}")
            findings.extend(f)
    return findings


def install_hook() -> int:
    git_dir = git("rev-parse", "--git-dir").strip()
    hooks = os.path.join(git_dir, "hooks")
    os.makedirs(hooks, exist_ok=True)
    hook = os.path.join(hooks, "pre-commit")
    me = os.path.abspath(__file__)
    body = f"""#!/bin/sh
# installed by secretgate
exec python3 "{me}" scan --staged
"""
    with open(hook, "w") as fh:
        fh.write(body)
    os.chmod(hook, 0o755)
    print(f"installed pre-commit hook -> {hook}")
    return 0


def report(findings: list[Finding], as_json: bool = False) -> int:
    if as_json:
        import json
        print(json.dumps([f._asdict() for f in findings], indent=2))
    elif not findings:
        print("secretgate: clean — no secrets found")
    else:
        order = {"high": 0, "medium": 1, "low": 2}
        for f in sorted(findings, key=lambda x: (order[x.severity], x.path, x.line)):
            print(f"[{f.severity.upper():6}] {f.path}:{f.line}  {f.rule}  {f.secret_preview}")
        print(f"secretgate: {len(findings)} finding(s). Fix before pushing, or mark the line with '# secretgate: allow'.")
    return 0 if not findings else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="secretgate", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan files for secrets")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--staged", action="store_true", help="scan staged diff (pre-commit)")
    s.add_argument("--history", action="store_true", help="scan all blobs in git history")
    s.add_argument("--json", action="store_true")
    s.add_argument("--fail-on-none", action="store_true", help="always exit 0")

    sub.add_parser("install", help="install as pre-commit hook")

    r = sub.add_parser("rules", help="list detection rules")
    r.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)

    if args.cmd == "rules":
        if args.json:
            import json
            print(json.dumps([{"rule": n, "severity": s} for n, _, s in RULES], indent=2))
        else:
            for n, _, s in RULES:
                print(f"{s:6} {n}")
            print(f"{'low':6} high-entropy (heuristic)")
        return 0
    if args.cmd == "install":
        return install_hook()

    if args.staged:
        findings = scan_staged()
    elif args.history:
        findings = scan_history()
    else:
        # v1.2.3 fail-closed (C c69 lesson: a clean verdict from a scan that
        # scanned nothing is the worst output a secret scanner can produce):
        # a nonexistent/undecodable PATH arg used to print 'clean' rc 0 —
        # same bless-by-invisibility class as the file-arg defect. Exit 2.
        if not os.path.exists(args.path):
            print(f"secretgate: path does not exist: {args.path}", file=sys.stderr)
            return 2
        findings = scan_working_tree(args.path)
    rc = report(findings, as_json=args.json)
    return 0 if args.fail_on_none else rc


if __name__ == "__main__":
    sys.exit(main())
