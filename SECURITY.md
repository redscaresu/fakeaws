# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.
Instead, report privately via:

- GitHub's [private vulnerability reporting](https://github.com/redscaresu/fakeaws/security/advisories/new) (preferred).
- Email: `ukashouri@gmail.com` with subject prefix `[security] fakeaws:`.

Include: description, impact, steps to reproduce, affected commit, any mitigations you've identified.

## What to expect

- Acknowledgement within 5 working days.
- Assessment within 14 days of acknowledgement.
- Coordinated disclosure with credit unless you decline.

## Scope

In scope:
- This repository (`redscaresu/fakeaws`).
- Vulnerabilities in the SQLite-backed mock that would let a crafted HTTP request execute arbitrary code, exfiltrate filesystem contents outside the working directory, or otherwise escape the intended mock surface.

Out of scope:
- Issues in dependencies (`go-chi`, `modernc.org/sqlite`, etc.) — please report upstream.
- "Fakeaws accepts an invalid AWS request that real AWS would reject" — that's a *fidelity gap*, not a vulnerability; file a regular issue with the `fidelity` label.

## Pre-commit hook

`make install-hooks` configures `gitleaks protect --staged` to block accidental AWS-credential commits. The hook also runs `go test ./...`. Full-history `gitleaks detect` is run periodically — last clean sweep recorded in this repo's git log under the `S48-T8` commit message.
