#!/usr/bin/env python3
"""Tip-address parity contract (B c29 rail shape, A c42 port).

Every copy of THIS repo's tip address must be the one address, and the
footer of the DEPLOYED page must equal the committed one. B's c29 audit
proved the danger class: a whole-page membership test on a page that
legitimately carries SIBLING fleet addresses (fleet deep links, team
footers) is forge-friendly — mutating the tip to a sibling addr stayed
green. So: compare footer-scoped SETS with exactly-one semantics, never
page-wide membership, and include the sibling addresses in a reject list.

Layers checked (all must hold or exit 1):
  1. index.html <footer> region carries EXACTLY ONE distinct EVM address
     and it == TIP_ADDR; B/C fleet addrs in the footer are a hard FAIL.
  2. Deployed Pages footer (live urllib fetch, browser UA, no-cache) has
     the same footer address set AND its address-bearing lines byte-match
     the committed footer's (B c29 live leg: a forger editing only the
     deployed artifact is caught; a deploy mid-flight retries like the
     c32 retry class, fail-closed after 4 attempts).
  3. README: every 'ETH: 0x…' tip line OUTSIDE the team-footer block (the
     team-footer line legitimately enumerates all 3 fleet addrs) == TIP.
  4. README team-footer line: the FIRST address (labeled 'A') == TIP.
  5. .github/FUNDING.yml custom list contains exactly one addr == TIP.
  6. .github/workflows/verify-release.yml: every require/WANT/A_ADDR
     value == TIP (receipt signer and tip addr are the same identity; if
     they ever diverge this step must be edited deliberately, not drift).
  7. SECURITY.md (if present): every addr == TIP (single-mailbox rule).
  8. REJECT set: B's and C's fleet addrs must never appear in any
     receive-side layer above (1,3,5,6,7).

No third-party imports (stdlib urllib only). Run from the repo root.
"""
import re
import sys
import time
import urllib.request

TIP_ADDR = "0xFD4090e27C1f946Ff01a265cAa7d4ACA662acC15"  # secretgate: allow public tip addr
SITE_PAGE = "https://tianzhicdev.github.io/secretgate/index.html"
FLEET_OTHERS = {  # sibling fleet addrs: a tip copy swapped to one of these = forgery class
    "0x5439bc46ac9cc70dfFC500611c6D845d7eE9eE5E".lower(): "B",
    "0xf232dcdc177b53981b4d805a48c79f239db8d0f9": "C",
}

ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")
failures = []


def die(msg):
    failures.append(msg)
    print(f"FAIL: {msg}")


def ok(msg):
    print(f"OK: {msg}")


def addrs(text):
    """Distinct addresses in text, lower-cased, document order."""
    seen, out = set(), []
    for m in ADDR_RE.findall(text):
        k = m.lower()
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def check_receive_side(layer, text):
    """Address set of a receive-side layer must be exactly {TIP}."""
    a = addrs(text)
    if a == [TIP_ADDR.lower()]:
        ok(f"{layer}: exactly one addr, == TIP")
    else:
        die(f"{layer}: address set {a} != [TIP {TIP_ADDR}] "
            f"(sibling/fleet addr in receive-side layer = B c29 forge class)")


def footer_of(page_html):
    m = re.search(r"<footer\b.*?</footer>", page_html, re.S)
    if not m:
        die("no <footer> region found")
        return ""
    return m.group(0)


def fetch_live(url):
    """urllib + browser UA + no-cache (B c17 CDN-read class), 4-attempt
    backoff (A c32/B c32 retry class) so a mid-deploy or CDN flake retries
    but a real mismatch still fails closed."""
    last = None
    for i in range(1, 5):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) tip-parity/1",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            })
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8")
        except Exception as e:  # noqa: BLE001 — retry any transport error, fail closed at cap
            last = e
            if i < 4:
                time.sleep(2 * i)
    die(f"live fetch failed after 4 attempts ({url}): {last}")
    return None


def main():
    page = open("index.html", encoding="utf-8").read()

    # 1. committed footer: exactly-one addr set, == TIP
    foot = footer_of(page)
    if foot:
        check_receive_side("committed footer", foot)

    # 2. live footer: same addr set AND same addr-bearing lines byte-match
    live = fetch_live(SITE_PAGE)
    if live is not None:
        live_foot = footer_of(live)
        if live_foot:
            check_receive_side("live footer", live_foot)
            committed_lines = sorted(
                ln.strip() for ln in foot.splitlines() if ADDR_RE.search(ln))
            live_lines = sorted(
                ln.strip() for ln in live_foot.splitlines() if ADDR_RE.search(ln))
            if committed_lines == live_lines:
                ok(f"live footer == committed footer ({len(committed_lines)} addr-bearing lines byte-match)")
            else:
                die("live footer != committed footer (deployed artifact drifted "
                    "from git — B c29 live-leg class)")

    # 3./4. README layers
    readme = open("README.md", encoding="utf-8").read()
    body = re.sub(r"<!-- team-footer:start -->.*?<!-- team-footer:end -->",
                  "", readme, flags=re.S)
    tip_lines = [ln for ln in body.splitlines()
                 if re.search(r"ETH:\s*0x[0-9a-fA-F]{40}", ln)]
    if not tip_lines:
        die("README has no 'ETH: 0x…' support tip line (layer went missing = "
            "silent-unpin class, c27)")
    for ln in tip_lines:
        check_receive_side("README tip line", ln)
    team = re.search(r"<!-- team-footer:start -->.*?<!-- team-footer:end -->",
                     readme, re.S)
    if not team:
        die("README team-footer block missing")
    else:
        first = addrs(team.group(0))[:1]
        if first == [TIP_ADDR.lower()]:
            ok("README team-footer: first (A-labelled) addr == TIP")
        else:
            die(f"README team-footer first addr {first} != TIP "
                "(fleet line order changed or A's copy swapped)")

    # 5. FUNDING.yml
    funding = open(".github/FUNDING.yml", encoding="utf-8").read()
    check_receive_side("FUNDING.yml", funding)

    # 6. verify-release.yml values
    vr = open(".github/workflows/verify-release.yml", encoding="utf-8").read()
    vals = re.findall(r"(?:require|WANT|A_ADDR)\s*[:=]\s*\"?(0x[0-9a-fA-F]{40})", vr)
    if not vals:
        die("verify-release.yml: no require/WANT/A_ADDR address found "
            "(locator drifted = silent-skip class)")
    bad = sorted({v for v in vals if v.lower() != TIP_ADDR.lower()})
    if bad:
        die(f"verify-release.yml: value(s) {bad} != TIP")
    ok(f"verify-release.yml: all {len(vals)} signer values == TIP")

    # 7. SECURITY.md if present
    try:
        sec = open("SECURITY.md", encoding="utf-8").read()
        check_receive_side("SECURITY.md", sec)
    except FileNotFoundError:
        ok("SECURITY.md absent — layer skipped by design")

    # 8. REJECT sweep: sibling fleet addrs must never appear in receive-side
    #    layers (README's team-footer block is exempt — it enumerates all 3
    #    by design; everything else is not).
    for name, txt in [("index.html", page), (".github/FUNDING.yml", funding),
                      (".github/workflows/verify-release.yml", vr),
                      ("README.md (outside team-footer)", body)]:
        for a in addrs(txt):
            if a in FLEET_OTHERS:
                die(f"{name}: sibling addr {a} ({FLEET_OTHERS[a]}) present — "
                    "tip copy swapped to a fleet sibling")

    if failures:
        print(f"\n{len(failures)} failure(s)")
        sys.exit(1)
    ok("tip parity: every layer agrees on one address, live == committed")


if __name__ == "__main__":
    main()
