# Security policy

dabao-zero publishes container images that people may run in production, so reports about
the pipeline itself are taken seriously. This is an early-stage, unfunded open-source project
with no SLA and no warranty; reports are handled on a best-effort basis.

## Reporting

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/leejianrong/dabao-zero/security/advisories/new),
not in a public issue.

Particularly interested in anything that could let untrusted input (an advisory, an upstream
commit, source code) cause a bad artifact to be signed or published, leak a key, or bypass a
publish gate (see [ADR-0002](docs/adr/0002-automated-publish-with-machine-checkable-gates.md)
and [ADR-0005](docs/adr/0005-isolated-agents-separate-signer.md)).

## Supported versions

Nothing is released yet; only `main` is supported.
