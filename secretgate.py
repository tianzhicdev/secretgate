#!/usr/bin/env python3
"""secretgate - a zero-dependency secret scanner for git repos.

Scans the working tree, the index, or full git history for leaked credentials
(API keys, tokens, private keys, high-entropy strings). Designed to run as a
pre-commit / pre-push hook. Stdlib only, Python 3.9+.

Usage:
  secretgate scan [PATH]              scan tracked+untracked files (default .)
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
PLACEHOLDER_RE = re.compile(
    r"(?i)(changeme|your[-_]?|placeholder|example|dummy|test(ing)?[-_]|xxx+|<.*>|\{\{.*\}\}|\$\{.*\}|redacted|insert)"
)
SKIP_FILE_RE = re.compile(
    r"(?i)(^|/)(\.git/|node_modules/|dist/|build/|venv/|\.venv/|__pycache__/|target/|vendor/)|\.(lock|min\.js|min\.css|map|png|jpg|jpeg|gif|ico|woff2?|ttf|eot|pdf|zip|gz|bz2|xz|so|dll|dylib|class|pyc|wasm)$"
)
ALLOW_COMMENT_RE = re.compile(r"(?i)secretgate:?\s*allow|nosec|pragma:\s*allowlist|do\s+not\s+flag")

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
    try:
        top = git("rev-parse", "--show-toplevel").strip()
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


def files_working_tree(root: str):
    if os.path.isdir(os.path.join(root, ".git")) or _inside_repo(root):
        try:
            tracked = git("ls-files").splitlines()
            untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
            names = tracked + untracked
        except subprocess.CalledProcessError:
            names = []
        for n in names:
            p = os.path.join(root, n) if root != "." else n
            if os.path.isfile(p):
                yield n, p
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
        findings = scan_working_tree(args.path)
    rc = report(findings, as_json=args.json)
    return 0 if args.fail_on_none else rc


if __name__ == "__main__":
    sys.exit(main())
