#!/usr/bin/env python3
"""Release assets x committed proofs parity (C c28 rail, A port, cycle 37;
credential-hardened c52 + c53).

C's ethkey-lite selftest pin (fc6671a) walks THREE rails between GitHub
releases and the committed proofs/ dir; my repos claimed the same
'every release carries a signed receipt' story but only pinned it in ONE
direction (receipts verify via CLI). A c37 audit of my own 3 repos against
this rail found REAL gaps (orphan assets, committed-never-attached drift,
a v1.0.0 release with zero assets) — fixed in the same commit that lands
this pin, so the baseline is green from day one.

Rails (all must hold or exit 1):
  (a) every release ASSET exists in proofs/ byte-identically (silently
      re-uploading an altered asset = stranger verifies != repo shows);
  (b) every committed version receipt in proofs/ is attached to a release
      (committed-but-never-uploaded = the claim is a lie for that version);
  (c) an asset's embedded version == its release tag's version, zero-
      normalized (v0.8 == v0.8.0 — C's own false-fail bug class).

Config per repo: REPO constant; VERSION_FILE_RE classifies committed
version receipts (fixtures excluded). Leg (c) reads releases from the
GitHub API; set RELEASES_JSON=/path/to/releases.json to run against a
saved snapshot (flip controls use this — (c) is data-driven and must be
provable non-vacuous locally).

Credential discipline (C c43 three legs, claimed + one leg added):
The unauthenticated api.github.com GET is a STRUCTURAL cap, not a
transient — 60 req/h per shared runner IP; retries cannot fix exhaustion
(my hookpack run 33352533925 attempt 1 went RED on exactly this after 4
retries). In CI the step passes GITHUB_TOKEN (per-job 5000/h).
  * Host-SCOPED attach (C c43) — Authorization is built ONLY when the
    request host is EXACTLY api.github.com. Host EQUALITY, not substring:
    the api host embedded in another URL's path/query must not earn it.
  * Cross-host REDIRECT STRIP (A c53 — the leg host-scope at attach time
    does NOT provide): urllib's redirect handler COPIES the caller's
    headers onto the redirect request, hostname changes included — a
    live two-hop catcher proves a token attached for host A rides a 302
    to host B. Asset downloads go github.com -> objects.githubusercontent.
    com; a token must never ride that arrow even if a future refactor
    attaches at the download leg, and an api-side redirect would smuggle
    it out the same way. Our opener therefore strips Authorization from
    every redirect whose target hostname differs from the source's.
  * Fail-closed wiring (C c43) — inside CI (GITHUB_ACTIONS=true) a
    missing token is a wiring defect: exit 2, never a silent degrade
    back to the 60/h shared-IP cap. Outside CI, unauthenticated is an
    honest local mode and the run SAYS so (an exemption that announces
    itself).
  * Structural != transient (C c43) — an HTTP 4xx (bad/expired token,
    404) fails FAST and names its status; only transport errors and 5xx
    retry (3 attempts, backoff). Retrying a 401 is theater.

--selftest runs the credential matrix offline (host-scope baits incl.
substring hosts, empty-token, the redirect-strip unit pair same-host /
cross-host, and the 4xx-vs-5xx classifier). Exit codes: 0 green,
1 violation, 2 bad usage / bad wiring. Run from the repo root; stdlib only.
"""
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = "secretgate"
API_ROOT = "https://api.github.com"
API_HOST = "api.github.com"
UA = "release-assets-parity"
# committed version receipts must match this (fixtures explicitly excluded)
VERSION_FILE_RE = re.compile(r"^(?!.*fixture).*v\d+\.\d+[^_]*\.(md|sig\.txt)$")
ASSET_VERSION_RE = re.compile(r"v(\d+)\.(\d+)(?:\.(\d+))?.*")


def die(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def ok(msg):
    print(f"OK: {msg}")


def auth_header():
    """Credential producer ONLY — callers must route through headers_for();
    returning the credential here is safe because the host check lives
    there."""
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        return {"Authorization": "Bearer " + tok}
    return {}


def headers_for(url):
    """Base headers + auth ONLY for an EXACT host match (never substring:
    the api host embedded in another URL's path/query must not earn it)."""
    h = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    host = urllib.parse.urlsplit(url).hostname
    if host == API_HOST:  # equality, not `in`
        h.update(auth_header())
    return h


class CrossHostAuthStrip(urllib.request.HTTPRedirectHandler):
    """Redirect handler: the base class copies the caller's headers onto
    the redirect request verbatim, so a token earned for host A rides a
    302 to host B (live-verified, c53). Strip Authorization whenever the
    redirect target's hostname differs from the source request's."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        src_host = urllib.parse.urlsplit(req.full_url).hostname
        dst_host = urllib.parse.urlsplit(newurl).hostname
        if src_host != dst_host and new.has_header("Authorization"):
            new.remove_header("Authorization")
        return new


_OPENER = urllib.request.build_opener(CrossHostAuthStrip)


def is_transient(exc):
    """Retry ONLY transport errors + 5xx. 4xx = structural (bad token,
    deleted release): retrying hides the real error and wastes budget."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500
    return True  # URLError, timeouts, connection resets


def get(url, raw=False, attempts=3):
    last = None
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers=headers_for(url))
            d = _OPENER.open(req, timeout=30).read()
            return d if raw else json.loads(d)
        except urllib.error.HTTPError as e:
            if not is_transient(e):
                die(f"HTTP {e.code} (structural — not retried) for {url}: "
                    "check token validity / asset exists")
            last = e
        except Exception as e:  # noqa: BLE001 - transport class, retry then die loud
            last = e
        if attempt < attempts - 1:
            time.sleep(2 ** attempt * 3)
    raise RuntimeError(f"GET {url} failed after {attempts} attempts: {last}")


def selftest():
    """Credential + redirect + classifier matrix, NO network. Every leg
    must hold or this exits 1 — the host-scope boundary and the
    cross-host redirect strip are proven by bait URLs and real Request
    objects, not asserted in a comment."""
    fails = []

    def expect(desc, cond):
        if not cond:
            fails.append(desc)

    # 1. exact api host earns the token when one is present
    os.environ["GITHUB_TOKEN"] = "SELFTEST-TOKEN"
    try:
        h = headers_for("https://api.github.com/repos/x/y/releases")
        expect("api.github.com did NOT earn Authorization",
               h.get("Authorization") == "Bearer SELFTEST-TOKEN")
        # 2. every other host never earns it (incl. substring baits)
        for u in ("https://github.com/o/r/releases/download/v1/a.md",
                  "https://objects.githubusercontent.com/x/y/a.md",
                  "https://example.com/?next=api.github.com",
                  "https://evil.example/api.github.com",
                  "https://api.github.com.evil.example/repos",
                  "https://notapi.github.com/repos"):
            h2 = headers_for(u)
            expect(f"token LEAKED to {u}", "Authorization" not in h2)
        # 3. no token -> no Authorization header anywhere, base headers intact
        del os.environ["GITHUB_TOKEN"]
        h3 = headers_for("https://api.github.com/repos/x/y/releases")
        expect("Authorization present with empty token", "Authorization" not in h3)
        expect("base UA lost", h3.get("User-Agent") == UA)
    finally:
        os.environ.pop("GITHUB_TOKEN", None)

    # 4. redirect strip: cross-host drops Authorization, same-host keeps it
    #    (mutation twin of the F4 class runs live against a catcher too).
    class _FP:  # minimal stand-in; header logic never touches fp
        pass
    hr = CrossHostAuthStrip()
    os.environ["GITHUB_TOKEN"] = "SELFTEST-TOKEN"
    try:
        orig = urllib.request.Request(
            "https://api.github.com/x", headers=headers_for("https://api.github.com/x"))
        expect("orig has no Authorization (setup broke)",
               orig.has_header("Authorization"))
        xhost = hr.redirect_request(orig, _FP(), 302, "Found", {},
                                    "https://objects.githubusercontent.com/y")
        expect("cross-host redirect KEPT the token (leak)",
               xhost is not None and not xhost.has_header("Authorization"))
        same = hr.redirect_request(orig, _FP(), 302, "Found", {},
                                   "https://api.github.com/z")
        expect("same-host redirect DROPPED the token (scope too tight)",
               same is not None and same.has_header("Authorization"))
    finally:
        os.environ.pop("GITHUB_TOKEN", None)

    # 5. classifier: 4xx structural, 5xx/transport transient
    from email.message import Message

    def mk(code):
        return urllib.error.HTTPError("u", code, "x", Message(), None)
    expect("401 treated transient", not is_transient(mk(401)))
    expect("403 treated transient", not is_transient(mk(403)))
    expect("404 treated transient", not is_transient(mk(404)))
    expect("500 treated structural", is_transient(mk(500)))
    expect("504 treated structural", is_transient(mk(504)))
    expect("URLError treated transient", is_transient(urllib.error.URLError("reset")))

    if fails:
        for f in fails:
            print("FAIL:", f)
        sys.exit(1)
    ok("release-assets-parity selftest (host-scope x6 baits, empty-token, "
       "cross-host redirect strip + same-host twin, classifier 4xx/5xx/transport)")


def norm(groups):
    return tuple(g or "0" for g in groups)


def main():
    if "--selftest" in sys.argv[1:]:
        selftest()
        return
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        if not os.environ.get("GITHUB_TOKEN", "").strip():
            print("FAIL: running in CI without GITHUB_TOKEN — wiring defect; "
                  "unauthenticated api.github.com is a 60/h SHARED-IP cap, "
                  "retries cannot fix exhaustion (A c51 class). Wire "
                  "'env: GITHUB_TOKEN: *** secrets.GITHUB_TOKEN }}'.")
            sys.exit(2)
    else:
        if not os.environ.get("GITHUB_TOKEN", "").strip():
            print("NOTE: no GITHUB_TOKEN (local mode) — unauthenticated "
                  "api.github.com, 60/h cap; CI must pass the token")

    snapshot = os.environ.get("RELEASES_JSON")
    if snapshot:
        with open(snapshot, encoding="utf-8") as f:
            rels = json.load(f)
        ok(f"releases snapshot: {snapshot} ({len(rels)} releases)")
    else:
        rels = get(f"{API_ROOT}/repos/tianzhicdev/{REPO}/releases?per_page=100")
    if not rels:
        die("repo reports zero releases")

    errors = []
    attached = set()
    for r in rels:
        tag = r["tag_name"]
        tv = re.fullmatch(r"v(\d+)\.(\d+)(?:\.(\d+))?", tag)
        if not tv:
            die(f"non-semver tag {tag}")
        if not r["assets"]:
            errors.append(f"{tag}: release has ZERO assets (no receipt attached)")
        for a in r["assets"]:
            name = a["name"]
            attached.add(name)
            av = ASSET_VERSION_RE.search(name)
            if not av:
                errors.append(f"{tag}: asset {name} is not version-named")
            else:
                if norm(av.groups()) != norm(tv.groups()):
                    errors.append(
                        f"{tag}: asset {name} version != tag version")
            local = os.path.join("proofs", name)
            if not os.path.isfile(local):
                errors.append(f"{tag}: asset {name} has NO committed file in proofs/")
                continue
            if snapshot:
                # flip harness: byte-leg runs vs committed files only
                ok(f"{tag}: {name} committed file present (snapshot mode)")
                continue
            live = get(a["browser_download_url"], raw=True)
            committed = open(local, "rb").read()
            if live != committed:
                errors.append(
                    f"{tag}: asset {name} bytes != committed proofs/{name} "
                    f"(sha256 {hashlib.sha256(live).hexdigest()[:12]} vs "
                    f"{hashlib.sha256(committed).hexdigest()[:12]})")
            else:
                ok(f"{tag}: asset == committed proofs/{name} "
                   f"({hashlib.sha256(committed).hexdigest()[:12]})")

    committed_vr = {f for f in os.listdir("proofs")
                    if VERSION_FILE_RE.match(f)}
    missing = sorted(committed_vr - attached)
    if missing:
        errors.append("committed version receipts never attached to any "
                      f"release: {missing}")
    else:
        ok(f"all {len(committed_vr)} committed version receipts attached")

    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        print(f"release<->proofs parity: {len(errors)} problem(s)")
        sys.exit(1)
    print(f"PASS: parity table: {len(rels)} releases, {len(attached)} assets, "
          f"{len(committed_vr)} committed version receipts")


if __name__ == "__main__":
    main()
