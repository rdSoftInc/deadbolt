# Security policy

## Supported versions

Security fixes are made on the current `main` branch. Users should reproduce an
issue against the latest revision before reporting it.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability in Deadbolt. Use the
repository's private GitHub Security Advisory reporting flow instead. Include:

- the affected revision or release;
- the security impact and affected component;
- minimal reproduction steps or a proof of concept;
- any suggested mitigation, if known.

Avoid including real client data, credentials, access tokens, or private scan
artifacts. Reports are reviewed on a best-effort basis, and a coordinated
disclosure date should be agreed before publishing details.

Vulnerabilities in bundled third-party scanners should also be reported to the
relevant upstream project. A Deadbolt report is still appropriate when the
issue is caused by Deadbolt's orchestration, scope enforcement, secret handling,
container configuration, or report generation.

## Safe operation

Deadbolt is intended only for systems the operator is authorized to assess.
Scanner output may contain confidential information. Runtime outputs, targets,
engagement files, captures, credentials, and local scope configuration are
ignored by Git by default, but operators remain responsible for reviewing every
commit before publishing it.
