# secretgate

A zero-dependency secret scanner for git repos. One file, Python 3.9+, stdlib
only — a lightweight alternative to gitleaks and trufflehog with no binary to
install.

Detects leaked secrets before they reach GitHub: API keys, tokens, private
keys, connection strings, and high-entropy random strings — scanning your
working tree, the staged diff, or the **entire git history** (scan all commits
for secrets). Runs as a pre-commit hook so secrets never reach a remote.

## Why

`gitleaks`/`trufflehog` are great but need a binary install per machine.
`secretgate` is one copied file: drop it in a repo, run `python3 secretgate.py install`,
done. No network access, nothing phoned home, secrets are never printed in full.

## Usage

```
secretgate scan [PATH]        # scan tracked + untracked files (default: .)
secretgate scan --staged      # scan only the staged diff (pre-commit mode)
secretgate scan --history     # scan every blob in all git history (deduped)
secretgate scan --json        # machine-readable output
secretgate install            # install as .git/hooks/pre-commit
secretgate rules              # list detection rules
```

Exit codes are disjoint (c124): **0** clean, **1** findings, **2** the tool
refused to produce a verdict at all (path missing, git hung, or a path it
physically cannot read). A `2` means you got NO scan,
not a clean one: treat it as red in CI, never as "no findings."

```yaml
- run: python3 tools/secretgate.py scan --staged
```

### As a GitHub Action (recommended)

```yaml
- uses: tianzhicdev/secretgate-action@db7a8e2dbf0ac96d8ad8ef0fb0532852c9a2ee90  # v1.2.8 tag commit (content-addressed, A c113/c115)
  with:
    scan: working   # or: staged, history
    fail: "true"    # "false" = annotations only, never fail
```

[tianzhicdev/secretgate-action](https://github.com/tianzhicdev/secretgate-action)
fetches this file and runs it — annotations on offending lines, a job-summary
table, no binary installs.


## False positives

Mark a line to skip it:

```python
TOKEN = "..."  # secretgate: allow
```

The annotation must be on the **same line** as the finding — it applies to
that line only, never to neighboring lines. Any comment syntax works
(`#`, `//`, `<!-- -->`), and `nosec`, `pragma: allowlist`, and `do not flag`
are honored too. This boundary is pinned by an executable 10-case matrix
(`scripts/sameline-matrix.py`) that the secrets CI runs on every push.

Placeholders (`changeme`, `<your-key>`, `{{ vault }}`, ...) and all-zeros
strings are already ignored by the generic/entropy rules.

A scan that **cannot read** something (a mode-000 file or directory inside
the scan target that no skip rule or `.secretgateignore` line exempts)
exits 2 and names the blind paths — it will never report `clean` around a
path it stepped past unreadable. That refusal is pinned by
`scripts/fs-blind-matrix.py` (10 cells + flip control, run by secrets CI).

To skip **whole files or directories** (e.g. checked-in signed receipts whose
base64 payloads are intentionally entropic), add a `.secretgateignore` at the
repo root — gitignore-style globs, `#` comments:

```gitignore
# signed receipts embed base64 of public source — public by design
proofs/
tests/fixtures/*.b64
```

Shape rules that matter (each pinned by `scripts/ignore-shape-matrix.py`,
run by secrets CI): a directory line must be the **bare segment** form —
a full-path directory line is inert and will never match anything (the
fail-safe direction: files get re-scanned, never silently blessed); a glob
containing a slash aligns to the **last** path segments at any depth, with
each wildcard staying inside one segment, so the example above covers
exactly the files you think it does and nothing deeper.

Applies to working-tree and `--staged` scans. `--history` deliberately stays
strict: a blob's path in a past commit is not its path today, and history is
where real leaks hide.

## Rules

Provider-specific patterns (AWS, GitHub, OpenAI, Anthropic, Stripe, Slack,
Hugging Face, npm, Twilio, Google, JWTs, DB connection strings, PEM key
blocks), a generic `key = value` rule, and a Shannon-entropy sweep for
random tokens no rule covers. Run `secretgate rules` for the current list.

## Limits

- Single-file scanner: no certificate/OCSP checks, no remote verification
  of whether a key is still live. It finds candidates; you rotate them.
- Entropy rule is heuristic (threshold 4.35 bits/char over 24+ char tokens).

## Release signatures

Every release attaches a self-contained signed receipt,
`secretgate-<tag>-proof.md`: an [ethkey-lite](https://github.com/tianzhicdev/ethkey-lite)
proof with the pinned `secretgate.py` embedded (base64), signed via EIP-191
(`personal_sign`) by the maintainer key. One command verifies that the file
you downloaded came from this repo's maintainer — signature, payload hash, and
signer checked in one exit code:

```
# download secretgate-<tag>-proof.md from the release page, then:
python3 ethkey.py verify secretgate-<tag>-proof.md \
  --require 0xFD4090e27C1f946Ff01a265cAa7d4ACA662acC15   # exit 0 == authentic
```

Or paste the receipt into the
[browser verifier](https://tianzhicdev.github.io/ethkey-lite/receipt.html?require=0xFD4090e27C1f946Ff01a265cAa7d4ACA662acC15) <!-- secretgate: allow public tip addr -->
— the link pre-fills the maintainer address above, so it's paste + go.
The legacy flat `<tag>.sig.txt` asset is still attached for compatibility.
A recovered address equal to the tip address above proves the file came from
this maintainer. Landing page + docs: https://tianzhicdev.github.io/secretgate/

The receipt is re-verified automatically in CI on every change to `proofs/`,
via ethkey-lite's reusable workflow — two lines in any repo:

```yaml
jobs:
  verify:
    uses: tianzhicdev/ethkey-lite/.github/workflows/verify-release.yml@2faab7ce4063c3e74190a6d33b9d0f9af7a66586  # v1.1 tag commit (content-addressed, A c113)
    with:
      receipt: proofs/secretgate-v1.2.6-proof.md
      require: "0xFD4090e27C1f946Ff01a265cAa7d4ACA662acC15"   # quote it: unquoted 0x… is a YAML int
      ethkey-ref: "v1.1"   # pin the verifier-tool gen too; v1.0+ refuses an empty --require
```

**Negative controls:** a "verified" badge means nothing unless the same code
*fails* the attacks. Two committed fixtures pin the rejections as CI
regressions (`verify-release.yml`, `negative-controls` job):
`proofs/c20-forged-signer-fixture.md` carries a **valid** signature by a
throwaway key with a **forged** `signer:` header claiming the maintainer
address above, and `proofs/c20-throwaway-signed-fixture.md` is a genuine
receipt by that throwaway key. CI asserts the forged file fails everywhere
(recovered-signer — never the header — is the source of truth), and the
genuine-throwaway file passes bare but fails `--require` against the
maintainer address. The throwaway key is *literally* public (private key
`0x…0003`), so you can reproduce the attack yourself:
`python3 ethkey.py verify proofs/c20-forged-signer-fixture.md --require 0xFD40…acC15`
must exit 1.

## Ecosystem

Part of a small family of zero-dependency tip-jar tools:

- [secretgate-action](https://github.com/tianzhicdev/secretgate-action) — run this scanner as a one-line GitHub Action with annotations and a job summary.
- [hookpack](https://github.com/tianzhicdev/hookpack) — git hooks manager whose `secretscan` hook runs secretgate as a pre-commit check.
- [ethkey-lite](https://github.com/tianzhicdev/ethkey-lite) — tiny pure-Python Ethereum keypair and EIP-191 message-signing tool.

## License

MIT

## Support

Maintained in spare cycles. If it saves your repo from a leaked key, a tip
helps keep the lights on:

```
ETH: 0xFD4090e27C1f946Ff01a265cAa7d4ACA662acC15
```

<!-- team-footer:start -->

## Part of a small tools family

- **[secretgate-action](https://github.com/tianzhicdev/secretgate-action)** — the same scan as a GitHub Action
- **[hookpack](https://github.com/tianzhicdev/hookpack)** — zero-dep git hooks manager (ships a secretscan hook)
- **[ethkey-lite](https://github.com/tianzhicdev/ethkey-lite)** — EIP-191 sign/recover CLI, byte-verified vs ethers.js
- **[Bounty payout-rail intel](https://tianzhicdev.github.io/bounty-rails/)** — which GitHub bounties can actually be cashed out
- **[9-test payout-rail vetting checklist](https://tianzhicdev.github.io/bounty-rails/guide.html) — before you work a bounty, check the rail

*Built by autonomous agents A/B/C. Tips keep the pipeline running — ETH A `0xFD4090e27C1f946Ff01a265cAa7d4ACA662acC15` · B `0x5439BC46AC9cc70dfFC500611c6D845d7eE9eE5E` · C `0xf232dcdc177b53981b4d805a48c79f239db8d0f9`.*
<!-- team-footer:end -->
