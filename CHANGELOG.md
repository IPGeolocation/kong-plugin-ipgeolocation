# Changelog

All notable changes are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-05

### Added

- Kong Gateway plugin `ipgeolocation`: IP intelligence and security from IPGeolocation.io MMDB databases,
  with no network calls on the request path.
- Pure LuaJIT, memory-mapped MMDB reader with bounds checks, pointer and depth limits and per-lookup work
  budgets; supports 24, 28 and 32-bit records, IPv4 and IPv6 trees and files larger than 2 GiB.
- Support for the Location (Standard, Advance), Country, ISP, ASN (Lite, Extended), Company, Security,
  Hosting, Residential Proxy and Abuse Contact databases and the combined products; several databases
  layer per field.
- 85 fields with `X-IPGeo-*` headers and the `none`, `minimal`, `standard` and `full` presets shared with
  the IPGeolocation.io Traefik plugin; custom header names; `true_false` or `one_zero` booleans; 12
  languages.
- Removal of every client-supplied `X-IPGeo-*` header (any case, underscores) and of custom header names.
- Security policy: country, continent and ASN allow and block lists; Tor, VPN, proxy, relay, residential
  proxy, anonymous, known attacker, bot (sparing known good bots), spam, cloud provider and corporate
  gateway flags; threat score threshold; exemptions; dry run; configurable status code and message;
  `fail_open`.
- Global-instance enrichment in the rewrite phase, so routes can match on enrichment headers.
- `kong.ctx.shared.ipgeolocation` and optional log serializer output for other plugins.
- Database loading in `configure`, retry of missing databases, optional validated refresh
  (`database_refresh_interval`), warnings on in-place modification.
- Unit, integration (Pongo) and end-to-end tests; benchmarks; a reader cross-check against
  `python-maxminddb`; examples for DB-less, Docker and Kubernetes; a database updater.

[Unreleased]: https://github.com/IPGeolocation/kong-plugin-ipgeolocation/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/IPGeolocation/kong-plugin-ipgeolocation/releases/tag/v0.1.0
