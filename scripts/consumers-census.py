#!/usr/bin/env python3
"""Consumers census: every fleet repo that EXECUTES secretgate-action must
consume the bytes our pins assert. A c123 ship of C's c112 law.

C c112 found my own c115 'fleet re-pin' claim was scoped by the re-pinner's
own repo list while a real consumer (C's repo) had silently executed a stale
generation, and B's repo was lagging. C's c114 correction is part of this
tool's shape: gh code-search returned total_count=0 for files that verifiably
exist in OUR repos — a 0-hit search cannot distinguish 'no consumers' from
'broken search' at our scale. So the census here is the PRIMITIVE C named:
per-repo contents read (1 API call/repo, exhaustive), and the repo table is
an explicit constant — a fleet join is an authored event, a fleet repo that
stops consuming is ALARMED, never silently absent.

Method: for each repo x { .github/workflows/secrets.yml (what executes),
README.md (what strangers paste — my c113 fifth edge) } fetch
contents@main via the GitHub API, b64-decode, collect every
`tianzhicdev/secretgate-action@REF`. Then resolve each distinct ref to its
CONTENT ADDRESS (raw fetch of action.yml@ref, sha256) and compare against
PIN_ACTION_SHA — the same sha this repo's pin-verify asserts the action step
EXECUTES. Required repos (my lane: re-pin is MY authored duty) must match
PIN_ACTION_REF exactly; tracked repos (B/C lanes: re-pin is THEIR authored
duty) mismatch prints as a WARN row with ref+resolved sha = evidence, not a
verdict on their lane (c65).

Vacuity is RED (c27): zero refs collected across the whole census means the
rail is blind, which is worse than no rail. Transport errors retry 4x with
backoff then fail CLOSED named — never silent-skip (c37); a ref that cannot
be fetched at all fails CLOSED naming repo+ref (E6b: a renamed/deleted tag
must not read as 'fine').

Env: PIN_ACTION_REF (40-hex, required), PIN_ACTION_SHA (64-hex, required).
Exit codes: 0 census green, 1 red (missing consumer / required-repo drift /
vacuous rail / fetch-dead ref), 2 bad usage.
"""
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
API = "https://api.github.com/"
RAW = "https://raw.githubusercontent.com/"

# Explicit consumer table (C c114 law: contents census, not search). The
# fleet is 5 repos; REQUIRED = A-lane repos whose re-pin duty is mine,
# TRACKED = co-agent lanes (WARN rows only — evidence, not lane edits).
REQUIRED = ("secretgate", "hookpack", "secretgate-action")
TRACKED = ("ethkey-lite", "bounty-rails")
SURFACES = (".github/workflows/secrets.yml", "README.md")

ACTION_AT_RE = re.compile(
    r"tianzhicdev/secretgate-action@([0-9a-zA-Z][0-9a-zA-Z._/-]*)")


def _headers() -> dict:
    # Optional token: the unauthenticated API quota is per-IP (60/hr) and a
    # census leg must not convert a quota flake into fleet-red CI; the CI
    # runner's GITHUB_TOKEN raises it. Absent token = local/stranger shape.
    h = {"User-Agent": UA}
    tok = os.environ.get("CENSUS_TOKEN") or ""
    if tok:
        h["Authorization"] = "token " + tok
    return h


def fetch(url: str) -> bytes:
    last = None
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers=_headers())
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001 - retry any transport error
            last = e
            if attempt < 3:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"GET {url} failed after 4 attempts: {last}")


def contents(repo: str, path: str) -> str | None:
    """Return decoded file text, or None on 404 (file genuinely absent —
    a DISTINCT, named outcome from a transport failure, which raises)."""
    url = f"{API}repos/tianzhicdev/{repo}/contents/{path}?ref=main"
    try:
        data = json.loads(fetch(url))
    except RuntimeError as e:
        if "HTTP Error 404" in str(e):
            return None
        raise
    return base64.b64decode(data["content"]).decode("utf-8", "replace")


def org_repos() -> list[str]:
    """Exhaustive owner-repo enumeration (A c128). Search is BLIND at our
    scale (C c114 + A c128: total_count=0 three ways for data that verifiably
    exists, rate-limit ruled out), so the consumer universe is LISTED, not
    indexed. Pagination terminates on a short page (measured: 45, page-2=0)."""
    names: list[str] = []
    page = 1
    while True:
        url = f"{API}users/tianzhicdev/repos?per_page=100&page={page}"
        data = json.loads(fetch(url))
        got = [r["name"] for r in data]
        names += got
        if len(got) < 100:
            return names
        page += 1


def wf_listing(repo: str) -> list[str] | None:
    """Every workflow filename in a repo, or None on 404 (dir genuinely
    absent = clean skip). Fetched via contents-at-HEAD with retry semantics
    identical to contents() — a transport error RAISES, fails closed."""
    url = f"{API}repos/tianzhicdev/{repo}/contents/.github/workflows?ref=HEAD"
    try:
        data = json.loads(fetch(url))
    except RuntimeError as e:
        if "HTTP Error 404" in str(e):
            return None
        raise
    return [e["name"] for e in data
            if e.get("name", "").endswith((".yml", ".yaml"))]


def discovery_leg(known: set[str]) -> int:
    """Unknown-consumer discovery (A c128, C c112 offer + c114 correction):
    the explicit REQUIRED/TRACKED table is authored duty, but a FLEET CLAIM
    that trusts the re-pinner's own repo list is where pointer-decay hides.
    Enumerate every owner repo; each one OUTSIDE the table gets its workflow
    dir listed and EVERY .yml/.yaml read (no name filter — a filtered probe
    is an approximation-matcher, my c125 law). A workflow there that
    executes secretgate-action = RED naming the repo (adjudicate + add,
    never silently skip). Fail-closed BOTH directions: a table repo missing
    from the org list is red too. Cross-org forks stay a stated blind spot
    (watch-condition in REPORT, not silence)."""
    bad = 0
    try:
        orgs = set(org_repos())
    except RuntimeError as e:
        print(f"::error::discovery: org enumeration fetch-FAIL ({e}) — "
              "cannot claim fleet-exhaustiveness; failing closed.",
              file=sys.stderr)
        return 1
    missing = sorted(known - orgs)
    if missing:
        print(f"::error::discovery: table repo(s) gone from org list: "
              f"{missing} — a renamed/deleted consumer is EXACTLY what "
              "this leg exists to catch.", file=sys.stderr)
        bad += 1
    probes = 0
    for repo in sorted(orgs - known):
        try:
            wfs = wf_listing(repo)
        except RuntimeError as e:
            print(f"::error::discovery: {repo}: workflow-dir listing dead "
                  f"({e}) — cannot clear what you cannot read.",
                  file=sys.stderr)
            bad += 1
            continue
        probes += 1
        if wfs is None:
            continue  # no workflows: clean skip, measured not assumed
        for nm in wfs:
            try:
                txt = contents(repo, f".github/workflows/{nm}")
            except RuntimeError as e:
                print(f"::error::discovery: {repo}/{nm} fetch-FAIL ({e}) — "
                      "fail-closed.", file=sys.stderr)
                bad += 1
                continue
            probes += 1
            if txt is None:
                continue
            if "tianzhicdev/secretgate-action" in txt:
                print(f"::error::discovery: UNKNOWN CONSUMER {repo} executes "
                      f"secretgate-action in .github/workflows/{nm} — add it "
                      "to the table + adjudicate, never silently skip.",
                      file=sys.stderr)
                bad += 1
    print(f"ok: discovery leg — org enumerated {len(orgs)} repos, "
          f"{len(orgs - known)} outside the table probed ({probes} calls), "
          "zero unknown executors")
    return bad


def main() -> int:
    ref = os.environ.get("PIN_ACTION_REF", "")
    want_sha = os.environ.get("PIN_ACTION_SHA", "")
    if not (re.fullmatch(r"[0-9a-f]{40}", ref)
            and re.fullmatch(r"[0-9a-f]{64}", want_sha)):
        print("usage: PIN_ACTION_REF (40-hex) PIN_ACTION_SHA (64-hex) "
              "env vars required", file=sys.stderr)
        return 2

    bad = 0
    total_refs = 0
    sha_cache: dict[str, str] = {}

    def resolve(r: str) -> str:
        if r not in sha_cache:
            url = f"{RAW}tianzhicdev/secretgate-action/{r}/action.yml"
            sha_cache[r] = hashlib.sha256(fetch(url)).hexdigest()
        return sha_cache[r]

    for repo in REQUIRED + TRACKED:
        found: set[str] = set()
        for surface in SURFACES:
            try:
                txt = contents(repo, surface)
            except RuntimeError as e:
                print(f"::error::census fetch dead: {repo}/{surface} ({e}) "
                      "— failing closed, census must not silent-skip.",
                      file=sys.stderr)
                bad += 1
                continue
            if txt is None:
                print(f"note: {repo}/{surface} absent (404 named, not "
                      "silently skipped)")
                continue
            hits = set(ACTION_AT_RE.findall(txt))
            found |= hits
            total_refs += len(hits)
        if not found:
            print(f"::error::{repo} executes ZERO secretgate-action refs — "
                  "a consumer that silently stopped consuming is exactly "
                  "what this census exists to catch (C c112).",
                  file=sys.stderr)
            bad += 1
            continue
        for r in sorted(found):
            try:
                got = resolve(r)
            except RuntimeError as e:
                print(f"::error::{repo} refs @{r} but the ref cannot be "
                      f"resolved to action.yml ({e}) — fails closed (a "
                      "moved-away tag is NOT 'fine').", file=sys.stderr)
                bad += 1
                continue
            if repo in REQUIRED:
                if r != ref or got != want_sha:
                    print(f"::error::{repo} (REQUIRED) executes @{r} "
                          f"(action.yml sha {got[:12]}..) but this repo "
                          f"executes/pins @{ref[:12]}.. "
                          f"({want_sha[:12]}..) — required-consumer DRIFT: "
                          "re-pin in the same commit as any pin move.",
                          file=sys.stderr)
                    bad += 1
                else:
                    print(f"ok: {repo} (REQUIRED) @ {r[:12]}.. sha "
                          f"{got[:12]}.. == pin (workspace + README fences)")
            else:
                if got == want_sha:
                    print(f"ok: {repo} (tracked) @ {r[:12]}.. resolves to "
                          "the pinned action bytes")
                else:
                    print(f"warn(tracked-lane, FYI only): {repo} @ {r[:12]}"
                          f".. resolves sha {got[:12]}.. != pinned "
                          f"{want_sha[:12]}.. — their re-pin duty (c65); "
                          "ref+sha printed as evidence, not verdict.")

    bad += discovery_leg(set(REQUIRED + TRACKED))
    if total_refs == 0:
        print("::error::vacuous census: 0 secretgate-action refs collected "
              "fleet-wide — the rail is blind (worse than none, c27).",
              file=sys.stderr)
        bad += 1
    if bad:
        print(f"consumers-census: FAIL ({bad} red leg(s))", file=sys.stderr)
        return 1
    print(f"consumers-census: OK — {total_refs} refs across "
          f"{len(REQUIRED) + len(TRACKED)} repos, required set == pin, "
          "every ref content-resolved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
