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


# c85 A4: dictionary-arm embeddings must SURVIVE (v1.2.4 fix); template
# dialects that merely START with the word must stay suppressed. Runtime-
# derived tokens (c25 law): the word is static vocabulary, the secret body is
# hash-derived, so no full token literal exists in any committed file.
import hashlib as _hl

_BASE = _hl.sha256(b"money-c85-fixture").hexdigest()
_DICT_EMBED = [
    # (word, iso-8601 splice position) -> mid-token embedding, generic path
    ("insert", 8), ("example", 12), ("your", 4), ("changeme", 10),
    ("redacted", 16),
]
_TEMPLATE_START = [
    "insert-key-here-abcdef0123456789ab", "example_secret_value_9f8e7d6c",
    "your-next-api-token-aaaa1111bbbb", "changeme-in-prod-please-99887766",
]


def a4_dictword_bounds() -> None:
    for word, pos in _DICT_EMBED:
        tok = _BASE[:pos] + word + _BASE[pos + len(word):][:40 - pos]
        tok = (tok[:40]) if len(tok) >= 40 else tok + _BASE[:40 - len(tok)]
        if word not in tok:
            die(f"A4 fixture vacuous: '{word}' not embedded in token")
        f = scan_text(f'api_secret = "{tok}"', "t")
        if not f:
            die(f"A4 dictword overmatch: '{word}'-embedded secret suppressed")
    for tmpl in _TEMPLATE_START:
        f = scan_text(f'api_secret = "{tmpl}"', "t")
        if f:
            die(f"A4 template dialect newly EXPOSED (false positive): {tmpl}")
    # entropy-path leg: token found at runtime so score_token(raw)==True and
    # no placeholder matches WITHOUT the word — only the word delta can kill
    rng = random.Random(85)
    word = "example"
    found = False
    for _ in range(50000):
        body = "".join(rng.choice(ALPHA) for _ in range(33))
        raw = body[:4] + body[4 + len(word):]
        tok = body[:4] + word + body[4 + len(word):]
        if score_token(tok) and score_token(raw) \
                and not PLACEHOLDER_RE.search(raw):
            f = scan_text(f'cache_key = "{tok}"', "t")  # no assignment keyword
            if not f:
                die("A4 entropy-path overmatch: embedded word silenced sweep")
            found = True
            break
    if not found:
        die("A4 entropy leg vacuous: no eligible token found")
    ok(f"A4 dictword-bounds: {len(_DICT_EMBED)} embeddings flagged, "
       f"{len(_TEMPLATE_START)} start-of-token templates suppressed, "
       "entropy path swept clean")


def a5_x5run_bounds() -> None:
    """v1.2.5 (c86): the bare `x{5,}` arm blessed any secret carrying a
    5-x run at EVERY gen (C c81 x5_midrun). Discriminator is position, not
    length: MID-value run = embed = must survive; run at token END = mask
    shape = stays suppressed (lowercase masked fixtures never reach the
    uppercase-only vendor rule; measured trade, not assumed)."""
    rng = random.Random(86)
    body = ""
    # c120 (C c111 loop-termination law): a data-dependent `while True`
    # spin has no natural exit if the break condition can never fire
    # (measured: score_token mutated to never-score hangs this leg at
    # >30s while the SAME mutation kills the bounded A1 corpus fast).
    # Cap = A1's 50000 bound (measured real cell needs <=7 iters; false-
    # score rate ~0.1% => cap unreachable on honest data). Exhaustion is
    # a NAMED vacuity die, never a silent spin.
    for _ in range(50000):
        body = "".join(rng.choice(ALPHA) for _ in range(40))
        if "x" not in body.lower() and score_token(body):
            break
    else:
        die("A5 seed exhausted: 50000 draws produced no eligible token "
            "(score_token broken or alphabet degenerate — vacuous cell)")
    embed = body[:15] + "xxxxx" + body[15:35]
    tail = body[:20] + "xxxxxxxx"
    assert score_token(embed)  # embed must ALSO reach the entropy sweep
    # (tail leg needs no score assert: the generic path checks PLACEHOLDER
    # BEFORE scoring, so suppression is placeholder-decided either way —
    # a score assert on it would be an over-requirement, c86 self-catch)
    if not scan_text(f'api_key = "{embed}"', "t"):
        die("A5 x5-embed overmatch: mid-token x-run silenced a real secret")
    if scan_text(f'api_key = "{tail}"', "t"):
        die("A5 mask regression: token-END long x-run newly EXPOSED")
    if scan_text('aws = "AKIA' + "x" * 16 + '"', "t"):
        die("A5 mask regression: lowercase masked AKIA fixture newly EXPOSED")
    # prose-arm tail bound (c86 do_not_flag fix): 'flaggable' is not an opt-in
    if scan_text(f'api_key = "{body}"  # do not flaggable', "t") == []:
        die("A5 prose-arm overmatch: 'do not flaggable' silenced the line")
    if scan_text(f'api_key = "{body}"  # please do not flag in audits', "t"):
        die("A5 documented opt-in 'do not flag' no longer suppresses")
    ok("A5 x5/prose-arm bounds: embed flagged, mask shapes suppressed, "
       "'flaggable' no longer an opt-in")


if __name__ == "__main__":
    a1_silent_corpus()
    a2_vocab_pin()
    a3_allow_bounds()
    a4_dictword_bounds()
    a5_x5run_bounds()
    print("placeholder-mutation-matrix: 5/5 PASS")
