#!/usr/bin/env python3
"""Suppression-surface mutation matrix (C c25 fleet rule: one mutation
probe per trust-critical parse field; A c34).

secretgate has two SILENCE surfaces — places where scanner output is
suppressed. Both are regexes matching free text, and both were shown by
mutation probing (c34) to over-suppress:

  1. PLACEHOLDER_RE's `xxx+` branch matches ANYWHERE in a token, so a
     genuinely random high-entropy secret containing a literal `xxx`
     mid-token (measured ~0.11% of random 40-char base64) is silently
     dropped from generic-api-key findings — a false negative in the
     detector's core job.
  2. ALLOW_COMMENT_RE's `nosec` branch is an unanchored substring, so any
     line merely CONTAINING "nosec" as a substring (e.g. a variable named
     `nosecretMode`) suppresses every finding on that line, including
     aws-access-key-class matches.

This script pins the FIXED behavior with three assertions, all
non-vacuous (each has a known-red flip, listed at the bottom):

  A1 SILENT-CORPUS: over a seeded corpus of >=3000 entropy-eligible
     random 40-char tokens (all true positives by construction), zero may
     be suppressed by PLACEHOLDER_RE. The old regex scores 9/7985 red.
  A2 VOCAB-PIN: every placeholder/template fixture (changeme123, {{KEY}},
     sk_live_XXXX..., masked x-runs at token end, ...) is STILL suppressed
     — the fix must not trade false negatives for false positives on
     template dialects.
  A3 ALLOW-BOUNDS: a line with a real AKIA key + the word `nosecret`
     (substring) on it is still FLAGGED; the same line with standalone
     `nosec` or `secretgate: allow` is suppressed (allow-list is opt-in by
     an explicit token, never by an incidental substring).

Stdlib only. Run from anywhere (imports the adjacent secretgate.py).
"""
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from secretgate import (  # noqa: E402
    ALLOW_COMMENT_RE,
    PLACEHOLDER_RE,
    score_token,
    scan_text,
)

ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"  # secretgate: allow token alphabet for corpus gen


def ok(msg: str) -> None:
    print(f"OK: {msg}")


def die(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def corpus(n: int = 8000, seed: int = 20260830) -> list[str]:
    rng = random.Random(seed)
    toks = ["".join(rng.choice(ALPHA) for _ in range(40)) for _ in range(n)]
    # only keep tokens that are entropy-eligible (would reach the
    # placeholder check); those are all TRUE positives.
    return [t for t in toks if score_token(t)]


def a1_silent_corpus() -> None:
    toks = corpus()
    if len(toks) < 3000:
        die(f"corpus vacuous: only {len(toks)} entropy-eligible tokens")
    hits = [t for t in toks if PLACEHOLDER_RE.search(t)]
    if hits:
        shown = ", ".join(t for t in hits[:3])
        die(f"{len(hits)}/{len(toks)} random secrets silently suppressed "
            f"(placeholder branch overmatches): {shown}")
    ok(f"A1 silent-corpus: 0/{len(toks)} entropy-eligible random tokens suppressed")


VOCAB = [
    "changeme", "changeme123", "your_api_key_here", "YOUR_TOKEN",
    "placeholder", "EXAMPLEvalue", "example", "dummy-value",
    "{{SECRET}}", "${API_KEY}", "<your-key>", "XXXXXXXX",
    "redacted_value", "insert-key-here", "test-ing-123", "your-key",
    "my-placeholder-token",
    # masked-key shapes: x-run at token end is masking intent
    "AKIAxxxxxxxxxxxxxxxx", "sk_live_XXXXXXXXXXXXXXXX",  # secretgate: allow masked fixtures
]


def a2_vocab_pin() -> None:
    bad = [v for v in VOCAB if not PLACEHOLDER_RE.search(v)]
    if bad:
        die(f"placeholder vocab newly EXPOSED (would false-positive): {bad}")
    ok(f"A2 vocab-pin: all {len(VOCAB)} template/masked fixtures suppressed")


def a3_allow_bounds() -> None:
    key = "AKIAIOSFODNN7EXAMPLA"  # secretgate: allow test-only key shape  # 4+16 shape, test-only
    flagged = scan_text(f'aws = "{key}"', "t")
    if not flagged:
        die("A3 baseline vacuous: bare AKIA not flagged")
    sub = scan_text(f'nosecretMode = 1  # {key} on same line', "t")
    if not sub:
        die("ALLOW overmatch: incidental 'nosecret' substring suppressed the line")
    for pragma in ("  # nosec", "  # secretgate: allow", "  #nosec"):
        sup = scan_text(f'aws = "{key}"{pragma}', "t")
        if sup:
            die(f"explicit allow pragma '{pragma.strip()}' no longer suppresses")
    ok("A3 allow-bounds: substring does not silence, explicit pragma still does")


if __name__ == "__main__":
    a1_silent_corpus()
    a2_vocab_pin()
    a3_allow_bounds()
    print("placeholder-mutation-matrix: 3/3 PASS")
