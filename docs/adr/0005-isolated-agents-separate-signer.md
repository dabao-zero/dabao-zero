# ADR-0005: Isolate agents and keep signing in a separate service

- Status: Accepted
- Date: 2026-10-16
- Deciders: Jian Rong Lee

## Context

Agents read untrusted text (advisories, upstream commits, source) and run builds. Prompt injection or malicious source could try to push, sign, or exfiltrate.

## Decision

Each attempt runs in an ephemeral, network-restricted sandbox that can reach only a source mirror and package proxy, and holds no credentials. Agents output a candidate patch and logs. The gate runner and signer run elsewhere, and signing uses keyless cosign tied to the CI identity, only after gates pass. Advisory and source text is treated as data, never as instructions.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Agent builds and pushes directly | One injection away from signed malware |
| Long-lived signing key | A stealable secret; keyless is simpler to reason about |

## Consequences

- Gets: a compromised agent can at worst produce a bad candidate, which the gates must catch.
- Costs: more moving parts, and the mirror/proxy limits some patches that need other network resources.
