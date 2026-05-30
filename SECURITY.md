# Security policy

This is a portfolio project built on the public Splunk Boss of the SOC v3
dataset. It contains no production systems and no real credentials.

## Reporting a vulnerability

If you find a security issue in the harness, the generated Splunk app, or the
CI pipeline, please open a private report through GitHub Security Advisories
("Report a vulnerability" on the Security tab) rather than a public issue.
I aim to respond within a few days.

## What runs on every change

CI gates each push and pull request, and re-runs weekly on a schedule:

- **ruff** (includes the `S` / flake8-bandit security rules) and **mypy --strict**
- **bandit** — Python static analysis
- **pip-audit** — known-CVE check against the locked dependencies
- **gitleaks** — secret scanning across the working tree and git history
- **zizmor** — GitHub Actions workflow security audit
- **CodeQL** — code scanning (enables automatically when the repo is public)

GitHub Actions are pinned by commit SHA, workflow permissions are read-only by
default, checkouts set `persist-credentials: false`, and the Splunk CI image is
pinned by digest. Dependency and action updates come through Dependabot.

## Known scanner matches that are not secrets

- `scenarios/*/fixtures/*.jsonl` carry synthetic AWS keys and other values from
  the published BOTS v3 dataset. They are public sample data, allowlisted in
  `.gitleaks.toml`.
- `Chang3me!` and the all-zero HEC token in the CI config are throwaway values
  for the ephemeral Splunk container that CI boots and destroys.
