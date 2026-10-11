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

## Exposure

fakeaws serves the AWS surface and the `/mock` admin endpoints with no authentication by default, on all interfaces. `/mock/reset` and `/mock/restore` discard state, so anything that can reach the port can wipe a run. On a shared or reachable host:

- `-bind 127.0.0.1` listens on loopback only (not inside a container, where it makes the published port unreachable).
- `-admin-token` or, better, `FAKEAWS_ADMIN_TOKEN` (a flag shows in `ps`) gates every `/mock` path: a present `Origin` that is not loopback is 403 before the token is read, so a page served from a non-loopback origin cannot drive it even with the token; then anything but `Authorization: Bearer <token>` is 401, which is what stops a page served from loopback (a dev server, say) that does not hold the token. The comparison is constant-time for a token of the right length (a wrong length is refused at once), and the token is never logged or echoed. `/healthz` and the AWS surface stay open.

With `-db <file>`, the db holds every secret a run wrote (Secrets Manager values, SSM SecureStrings, IAM access keys). When fakeaws creates it, the db, its `-wal`/`-shm`, the `.snapshot` that `/mock/snapshot` writes (through a `.snapshot.tmp` it renames) and a db `/mock/restore` recreates are 0600 (owner only). A db that already exists keeps its mode, so `chmod 600` one (and its `-wal`/`-shm`) created by an older fakeaws.

## Pre-commit hook

`make install-hooks` configures `gitleaks protect --staged` to block accidental AWS-credential commits. The hook also runs `go test ./...`. Full-history `gitleaks detect` is run periodically — last clean sweep recorded in this repo's git log under the `S48-T8` commit message.
