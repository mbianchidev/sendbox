# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/mbianchidev/sendbox/security/advisories/new)
(the repository's **Security** tab, then **Report a vulnerability**). Do not
open public issues, pull requests, or discussions for vulnerabilities.

Include what you can of the following:

- the SendBox version (`sendbox --version`), runtime (Apple, Kata, or
  Hyperlight), and host platform;
- the configuration and command needed to reproduce, with secrets removed;
- the boundary you were able to cross and its impact, such as a guest reaching
  the host, egress outside the allowlist, or a credential reaching the guest.

The report stays private while it is investigated, fixed, and disclosed
through a GitHub security advisory.

## Supported versions

Only the [latest release](https://github.com/mbianchidev/sendbox/releases/latest)
receives security fixes. Upgrade to it before reporting, and confirm the issue
still reproduces there.

## Scope

The [security model](docs/security-model.md) describes the boundaries SendBox
enforces and the assumptions it makes. The README's
[limitations and security expectations](README.md#limitations-and-security-expectations)
lists behavior that is known and intended, such as the writable shared
workspace and credentials deliberately delivered to an agent.
