# Security policy

## Reporting a vulnerability

Email **hello@auditail.io** with "Security" in the subject. Please don't open a public issue for a vulnerability.

Include what you found, how to reproduce it, and what an attacker could do with it. We'll reply within 2 business days, keep you updated while we fix it, and credit you in the release notes if you'd like.

In scope: the SDKs and verifier in this repository (`sdk-js`, `sdk-python`), and the hosted service at api.auditail.io and app.auditail.io.
Out of scope: denial-of-service testing against the hosted service, social engineering, and anything that touches other customers' data. Only test with accounts and data that are yours.

## How Auditail is designed to fail

- With a server-side policy, if Auditail can't be reached, actions are **denied**.
- A rule that throws an error **blocks** the action.
- An action that needs human approval never runs without one.
- Agent keys can never approve requests, change policies or lift a freeze.

More detail, including data location, subprocessors and what we don't have yet: https://auditail.io/docs/security

## Verifying what we sign

Receipts, checkpoints, reports and decision bundles are signed with Ed25519. The public keys are published at
https://api.auditail.io/.well-known/auditail-keys.json and pinned in this repository in `AUDITAIL_PUBLIC_KEYS.json`.
