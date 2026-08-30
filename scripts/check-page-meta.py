#!/usr/bin/env python3
"""Page meta-surface contract (B c20/c21 shape pattern, A c30).

B's railsite generator ASSERTS its emitted meta shape (EXACTLY one canonical,
one og:url, ...). This site is static hand-written HTML, so the same shape
asserts run against the committed index.html in CI: every social/SEO meta tag
must be present EXACTLY once, values must be internally consistent
(og:title == <title>, og:description == meta description, og:url == SITE_URL),
and no template placeholder dialect may survive in the page.

Checks (all must hold or exit 1):
  1. index.html parses with html.parser.
  2. EXACTLY one <link rel="canonical">, href == SITE_URL.
  3. EXACTLY one <link rel="icon"> of type image/svg+xml with a
     data:image/svg+xml URI href (B c20 entropy-clean pattern).
  4. og: properties — type(website), site_name, title, description, url —
     each EXACTLY once; url == SITE_URL.
  5. twitter: tags — card(summary), title, description — each EXACTLY once.
  6. og:title == <title> text; og:description == meta[name=description]
     content; twitter:title/description mirror the same pair (pairwise:
     the crawl/social signals can never disagree silently).
  7. No leftover placeholder token dialect (@slot@, {{slot}}, ${slot}, %s)
     anywhere in the page (B c19 '@canonical@'-in-the-wild class).

No third-party imports (stdlib html.parser only). Run from the repo root.
"""
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

SITE_URL = "https://tianzhicdev.github.io/secretgate/"
SITE_NAME = "secretgate"
PAGE = "index.html"


def die(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def ok(msg):
    print(f"OK: {msg}")


class Collect(HTMLParser):
    """Collect every <title>, <meta>, and <link> as (tag, attrs) tuples."""

    def __init__(self):
        super().__init__()
        self.tags = []          # list of (name, attrs-dict)
        self.titles = []
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.titles.append(data)


def count_meta(tags, kind, name):
    return [v for t, a in tags
            if t == "meta" and a.get(kind) == name
            for v in [a.get("content", "")]]


def main():
    root = Path(__file__).resolve().parent.parent
    page = (root / PAGE).read_text(encoding="utf-8")

    c = Collect()
    c.feed(page)
    c.close()
    if len(c.titles) != 1:
        die(f"expected exactly 1 <title>, found {len(c.titles)}")
    title = c.titles[0].strip()
    ok(f"exactly 1 <title>: {title!r}")

    # 2. canonical
    canon = [a.get("href", "") for t, a in c.tags
             if t == "link" and a.get("rel") == "canonical"]
    if len(canon) != 1:
        die(f"expected exactly 1 canonical link, found {len(canon)}")
    if canon[0] != SITE_URL:
        die(f"canonical href is {canon[0]!r}, expected {SITE_URL!r}")
    ok(f"canonical == {SITE_URL}")

    # 3. favicon (data-URI SVG, B c20 pattern)
    icons = [a for t, a in c.tags
             if t == "link" and a.get("rel") == "icon"]
    if len(icons) != 1:
        die(f"expected exactly 1 icon link, found {len(icons)}")
    if icons[0].get("type") != "image/svg+xml" or \
            not icons[0].get("href", "").startswith("data:image/svg+xml,"):
        die("icon link must be type image/svg+xml with a data: URI href")
    ok("exactly 1 data-URI SVG favicon")

    # 4/5. og: + twitter: each EXACTLY once
    og = {p: count_meta(c.tags, "property", p)
          for p in ("og:type", "og:site_name", "og:title",
                    "og:description", "og:url")}
    for p, v in og.items():
        if len(v) != 1:
            die(f"expected exactly 1 {p}, found {len(v)}")
    tw = {p: count_meta(c.tags, "name", p)
          for p in ("twitter:card", "twitter:title", "twitter:description")}
    for p, v in tw.items():
        if len(v) != 1:
            die(f"expected exactly 1 {p}, found {len(v)}")
    ok("og:* x5 and twitter:* x3 each present EXACTLY once")

    if og["og:type"][0] != "website":
        die(f"og:type is {og['og:type'][0]!r}, expected 'website'")
    if og["og:site_name"][0] != SITE_NAME:
        die(f"og:site_name is {og['og:site_name'][0]!r}, expected {SITE_NAME!r}")
    if og["og:url"][0] != SITE_URL:
        die(f"og:url is {og['og:url'][0]!r}, expected {SITE_URL!r}")
    if tw["twitter:card"][0] != "summary":
        die(f"twitter:card is {tw['twitter:card'][0]!r}, expected 'summary'")
    ok("og:type=website, og:site_name, og:url==SITE_URL, twitter:card=summary")

    # 6. pairwise consistency with the source-of-truth tags
    desc = count_meta(c.tags, "name", "description")
    if len(desc) != 1:
        die(f"expected exactly 1 meta description, found {len(desc)}")
    for tag, want in (("og:title", title), ("og:description", desc[0]),
                      ("twitter:title", title),
                      ("twitter:description", desc[0])):
        vals = og.get(tag) if tag in og else tw.get(tag)
        got = (vals or [""])[0]
        if got != want:
            die(f"{tag} != source-of-truth value:\n  got  {got!r}\n  want {want!r}")
    ok("og:title/og:description/twitter:title/twitter:description all "
       "byte-equal to <title> and meta description (pairwise pin)")

    # 7. no placeholder dialect survives. Brace patterns require a
    # whitespace-free slot name: real prose examples like "{{ vault }}" (a
    # .secretgateignore snippet on this very page) are NOT template slots;
    # B's c19 accident shipped the slot NAME itself ('@canonical@'), which
    # these patterns still catch.
    for pat, label in ((r"@[a-zA-Z_][a-zA-Z0-9_]*@", "@slot@"),
                       (r"\{\{[A-Za-z_][A-Za-z0-9_]*\}\}", "{{slot}}"),
                       (r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", "${slot}")):
        hits = re.findall(pat, page)
        if hits:
            die(f"placeholder dialect {label} survived: {hits[:3]}")
    ok("no @slot@ / {{slot}} / ${slot} placeholder tokens in page")

    print(f"PASS: {PAGE} meta-surface contract")


if __name__ == "__main__":
    main()
