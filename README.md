# secretgate

A zero-dependency secret scanner for git repos. One file, Python 3.9+, stdlib only.

Finds leaked API keys, tokens, private keys, connection strings, and
high-entropy random tokens in your working tree, staged diff, or **entire git
history** — designed to run as a pre-commit hook so secrets never reach a remote.

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

Exit code is 1 when findings exist, 0 when clean — chain it in CI:

```yaml
- run: python3 tools/secretgate.py scan --staged
```

### As a GitHub Action (recommended)

```yaml
- uses: tianzhicdev/secretgate-action@v1.2.3
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

To skip **whole files or directories** (e.g. checked-in signed receipts whose
base64 payloads are intentionally entropic), add a `.secretgateignore` at the
repo root — gitignore-style globs, `#` comments:

```gitignore
# signed receipts embed base64 of public source — public by design
proofs/
tests/fixtures/*.b64
```

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
    uses: tianzhicdev/ethkey-lite/.github/workflows/verify-release.yml@v0.8
    with:
      receipt: proofs/secretgate-v1.2.1-proof.md
      require: "0xFD4090e27C1f946Ff01a265cAa7d4ACA662acC15"   # quote it: unquoted 0x… is a YAML int
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
