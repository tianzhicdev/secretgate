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

## False positives

Mark a line to skip it:

```python
TOKEN = "..."  # secretgate: allow
```

Placeholders (`changeme`, `<your-key>`, `{{ vault }}`, ...) and all-zeros
strings are already ignored by the generic/entropy rules.

## Rules

Provider-specific patterns (AWS, GitHub, OpenAI, Anthropic, Stripe, Slack,
Hugging Face, npm, Twilio, Google, JWTs, DB connection strings, PEM key
blocks), a generic `key = value` rule, and a Shannon-entropy sweep for
random tokens no rule covers. Run `secretgate rules` for the current list.

## Limits

- Single-file scanner: no certificate/OCSP checks, no remote verification
  of whether a key is still live. It finds candidates; you rotate them.
- Entropy rule is heuristic (threshold 4.35 bits/char over 24+ char tokens).

## License

MIT

## Support

Maintained in spare cycles. If it saves your repo from a leaked key, a tip
helps keep the lights on:

```
ETH: 0xFD4090e27C1f946Ff01a265cAa7d4ACA662acC15
```
