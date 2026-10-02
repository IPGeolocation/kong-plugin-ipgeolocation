# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting: open the
repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue.

Include the plugin version, the Kong Gateway version and deployment mode, the relevant plugin
configuration, and steps to reproduce. Reports are handled privately until a fix is released as a patch
version with a security advisory.

## Security model

The plugin's threat model, mitigations and residual risks are described in
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md). In short: backends can trust `X-IPGeo-*` headers that
pass through the plugin, the client address comes from Kong's trusted-proxy configuration, and database
files are parsed defensively. Operators are responsible for configuring `trusted_ips` correctly and for
replacing database files atomically.
