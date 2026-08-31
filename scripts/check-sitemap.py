#!/usr/bin/env python3
"""sitemap-lastmod freshness contract (B c22 class, enforced from the outside).

B's railsite generator EMITS sitemap.xml, so lastmod can never drift there.
This site is static hand-written HTML, so instead the committed sitemap must
TRACK git history: lastmod must equal the date of the most recent commit that
touched the site's page content (PAGE_PATHS). If a PR edits the page and not
the sitemap, this check goes red in CI.

Checks (all must hold or exit 1):
  1. sitemap.xml parses as XML (minidom) and the root is <urlset>.
  2. EXACTLY one <url> with exactly one <loc> and one <lastmod>.
  3. <loc> == SITE_URL exactly.
  4. <lastmod> is a valid ISO date (YYYY-MM-DD).
  5. <lastmod> == git committer date (short) of the last commit touching
     PAGE_PATHS.

No third-party imports; git via subprocess. Run from the repo root (CI
checks out with fetch-depth: 0 so full history is available).
"""
import datetime
import subprocess
import sys
from pathlib import Path
from xml.dom import minidom

SITE_URL = "https://tianzhicdev.github.io/secretgate/"
PAGE_PATHS = ["index.html"]
SITEMAP = "sitemap.xml"


def die(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def ok(msg):
    print(f"OK: {msg}")


def main():
    root = Path(__file__).resolve().parent.parent
    sm = root / SITEMAP
    if not sm.is_file():
        die(f"{SITEMAP} missing")
    try:
        dom = minidom.parseString(sm.read_bytes())
    except Exception as e:  # noqa: BLE001 - report any parse failure
        die(f"{SITEMAP} does not parse: {e}")
    if dom.documentElement.tagName != "urlset":
        die(f"root element is <{dom.documentElement.tagName}>, expected <urlset>")

    urls = dom.getElementsByTagName("url")
    if len(urls) != 1:
        die(f"expected exactly 1 <url>, found {len(urls)}")
    locs = urls[0].getElementsByTagName("loc")
    mods = urls[0].getElementsByTagName("lastmod")
    if len(locs) != 1 or len(mods) != 1:
        die(f"url must have exactly one loc and one lastmod, "
            f"got {len(locs)} loc / {len(mods)} lastmod")

    loc = locs[0].firstChild.data.strip()
    lastmod = mods[0].firstChild.data.strip()
    if loc != SITE_URL:
        die(f"<loc> is '{loc}', expected '{SITE_URL}'")
    ok(f"loc == {SITE_URL}")

    try:
        datetime.date.fromisoformat(lastmod)
    except ValueError:
        die(f"<lastmod> '{lastmod}' is not an ISO date")
    ok(f"lastmod is a valid ISO date: {lastmod}")

    git = subprocess.run(
        ["git", "log", "-1", "--format=%cd", "--date=short", "--", *PAGE_PATHS],
        cwd=root, capture_output=True, text=True, timeout=60,
    )
    if git.returncode != 0:
        die(f"git log failed: {git.stderr.strip()}")
    truth = git.stdout.strip()
    if not truth:
        die("git log found no commit touching PAGE_PATHS "
            "(shallow checkout? CI must use fetch-depth: 0)")
    if lastmod != truth:
        die(f"sitemap lastmod '{lastmod}' != last page-content commit date "
            f"'{truth}' — update {SITEMAP} in this PR (stale companion file, "
            f"B c22 class)")
    ok(f"lastmod tracks git truth ({truth})")
    print("sitemap freshness contract: PASS")


if __name__ == "__main__":
    main()
