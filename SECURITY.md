# Security Policy

## Reporting a Vulnerability

If you believe you've found a security issue in `secretgate` or
[`secretgate-action`](https://github.com/tianzhicdev/secretgate-action), please
report it **privately** via a GitHub security advisory rather than a public
issue:

1. Go to <https://github.com/tianzhicdev/secretgate/security/advisories/new>
2. Describe the issue, affected versions, and — if possible — a minimal
   reproduction.

Please do not open a public issue, PR, or discussion thread describing an
unfixed vulnerability.

**Response window:** expect an initial response within **7 days**. If you don't
hear back within that window, feel free to follow up on the advisory.

## Scope

What's in scope:

- Anything that lets `secretgate` **exfiltrate, transmit, or fully print
  secrets** it scans. The scanner is offline by design (stdlib only, no network
  calls) and only ever prints truncated previews (`abcd…wxy (38 chars)`). Any
  deviation from that is a vulnerability.
- Path traversal, command injection, or arbitrary file reads via crafted
  repository contents, file names, git references, or history (`scan`,
  `--staged`, `--history` code paths all shell out to `git` on your behalf).
- Unsafe behavior of the `install` command (writing `.git/hooks/pre-commit`).
- Vulnerabilities in the GitHub Action wrapper, including anything that would
  let a pull request from a fork leak scan results or run attacker-controlled
  code on the runner beyond its stated purpose.
- Crashes or unbounded resource consumption triggered by ordinary-ish input
  that would make the tool unusable as a pre-commit hook or CI gate.

What's generally **out** of scope:

- Missed detections (false negatives) and false positives. Detection coverage
  is best-effort: the tool finds candidates, it does not verify keys are live,
  and the entropy rule is a heuristic.
- Findings in scanned repositories themselves (i.e., a leaked secret that the
  tool correctly *reported* is not a `secretgate` vulnerability).
- Issues requiring you to already have write access to the maintainer's repos
  or runner environment.
- Theoretical hardening suggestions without a concrete exploit path — those are
  welcome as regular issues, just not advisories.

## Safe Harbor

If you conduct your research in good faith — no access to other users' data,
no modification or destruction of data, no denial-of-service attacks, and no
public disclosure before we've had a chance to respond — we consider your
research authorized. We will not pursue legal action against researchers who
follow this policy, and we will not file complaints against tools or accounts
used solely for permitted research. If you're unsure whether something is in
scope, ask via the advisory form before testing.

## Acknowledgments

We're happy to credit researchers publicly in the advisory (or anonymously, at
your preference) once a fix is released.

At the maintainer's **sole discretion**, confirmed security reports may
additionally be thanked with a discretionary tip or bounty in ETH:

```
ETH: 0xFD4090e27C1f946Ff01a265cAa7d4ACA662acC15
```

**To be crystal clear:** this is *not* a paid-bounty program. There is no
bounty table, no promised amounts, no eligibility criteria, and no obligation
on the maintainer's part. `secretgate` is a free MIT-licensed tool maintained in
spare cycles; any payment is an optional goodwill gesture, decided case by case,
and may be declined or deferred for any reason. **Never let the possibility of a
payment influence whether you report a vulnerability — please report it either
way.** Do not hold a fix hostage waiting for payment terms.
