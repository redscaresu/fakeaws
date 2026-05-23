---
name: Bug report
about: Mock behavior diverges from real AWS, or fakeaws crashes.
title: '[bug] '
labels: bug
assignees: ''
---

## Summary

<!-- One sentence describing what's wrong. -->

## Steps to reproduce

```bash
# example
./fakeaws --port 8082 &
curl -X POST 'http://localhost:8082/iam' -d 'Action=CreateRole&Version=2010-05-08&RoleName=...'
```

## Expected behavior

<!-- What did real AWS return? Wire format matters here — include raw HTTP request + response if you have it. -->

## Actual behavior

<!-- What did fakeaws return? Raw HTTP request + response. -->

## Environment

- fakeaws commit: <!-- `git rev-parse --short HEAD` -->
- OS / arch:
- Go version:
- terraform-provider-aws version (if applicable):

## Type of issue

- [ ] Crash / panic in fakeaws
- [ ] Fidelity gap: fakeaws accepts a request that real AWS rejects
- [ ] Fidelity gap: fakeaws rejects a request that real AWS accepts
- [ ] Wrong wire format (Query-RPC, JSON 1.0/1.1, REST/XML, REST/JSON)
- [ ] Wrong error code/shape (terraform-provider-aws expects a specific code)
- [ ] FK enforcement bug
- [ ] State machine bug (Enabled/Disabled/PendingDeletion transitions)
- [ ] Coverage audit failed (TestFullCoverageAudit / TestRegressionSeedAuditManifestMatchesHandlers)
