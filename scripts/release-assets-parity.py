#!/usr/bin/env python3
"""Release assets x committed proofs parity (C c28 rail, A port, cycle 37).

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

No third-party imports. Network read-only, public data only.
"""
import hashlib
import json
import os
import re
import sys
import urllib.request

REPO = "secretgate"
BASE = "https://api.github.com"
UA = "release-assets-parity"
# committed version receipts must match this (fixtures explicitly excluded)
VERSION_FILE_RE = re.compile(r"^(?!.*fixture).*v\d+\.\d+[^_]*\.(md|sig\.txt)$")
ASSET_VERSION_RE = re.compile(r"v(\d+)\.(\d+)(?:\.(\d+))?.*")


def die(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def ok(msg):
    print(f"OK: {msg}")


def get(url, raw=False):
    # c37 first CI run caught a transient read-timeout on a raw asset fetch
    # (GitHub release-asset CDN hiccups are real; hookpack leg green,
    # secretgate/action legs died at 30s). One retry pass with backoff,
    # then fail loud — never silent-skip a leg.
    last = None
    for attempt in range(4):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": UA,
                              "Accept": "application/vnd.github+json"})
            d = urllib.request.urlopen(req, timeout=30).read()
            return d if raw else json.loads(d)
        except Exception as e:  # noqa: BLE001 - retry any transport error
            last = e
            if attempt < 3:
                import time
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"GET {url} failed after 4 attempts: {last}")


def norm(groups):
    return tuple(g or "0" for g in groups)


def main():
    snapshot = os.environ.get("RELEASES_JSON")
    if snapshot:
        with open(snapshot, encoding="utf-8") as f:
            rels = json.load(f)
        ok(f"releases snapshot: {snapshot} ({len(rels)} releases)")
    else:
        rels = get(f"{BASE}/repos/tianzhicdev/{REPO}/releases?per_page=100")
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
