# Security review

Scope: the plugin's code (version 0.1.0), its configuration surface and the operational procedures it
documents. Kong Gateway itself, the operating system and IPGeolocation.io's data are outside the scope.

## Assets and trust boundaries

Upstream services rely on two things: that `X-IPGeo-*` headers describe the real client, and that the
configured policy keeps unwanted traffic out.

| Boundary | Trust |
|---|---|
| Client to Kong | Untrusted: every header and every address claim. |
| Trusted proxies to Kong | Trusted exactly as far as `trusted_ips` says. |
| Database files | Trusted source, parsed defensively as untrusted input. |
| Kong configuration | Trusted (operators, Admin API, control plane), validated by the schema. |

## Threats and mitigations

| Threat | Mitigation | Verified by |
|---|---|---|
| A client sends `X-IPGeo-*` headers to claim another location or a clean reputation. | Every header in the namespace is removed before enrichment: any letter case, `_` treated as `-`, custom header names too, on every request including private and exempt clients. Global instances do this before routing. | Unit handler tests; end-to-end spoofing and routing checks |
| A client hides a spoofed header after many others, past the 100 headers Lua reads by default. | Headers are enumerated without a limit (`ngx.req.get_headers(0)`). | End-to-end check with 150 headers; the unit mock asserts the call |
| A client forges its address with `X-Forwarded-For`, `X-Real-IP` or `Forwarded`. | The plugin uses only `kong.client.get_forwarded_ip()`, the result of Kong's real-IP processing. The README explains `trusted_ips` and warns against trusting everything. | Unit test; end-to-end checks with recursive and untrusted `X-Forwarded-For` |
| An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) avoids IPv4 data. | Mapped addresses are converted to IPv4 before lookup and policy. | Unit and end-to-end tests |
| Database content injects headers (CR/LF) or oversized values. | Control characters are removed, values are capped at `max_value_length` on a UTF-8 boundary, and the `full` preset excludes unbounded lists. Kong's PDK validates header values as well. | Unit tests with a crafted database |
| A malicious or corrupt database causes out-of-bounds reads, loops, deep recursion or unbounded work. | Every read is bounds-checked; pointers must land inside the data section and may not point to pointers; nesting is limited to 32 levels; each extraction is limited to 20,000 steps, 256 KiB and 16 KiB per string; opening validates metadata, the search tree's size against the file and the data section separator. A bad record fails the lookup, which follows `fail_open`; it does not crash the worker. | Unit tests with crafted files; differential tests |
| A database file is rewritten in place while mapped, causing torn reads or `SIGBUS`. | Documented update rule (temporary file and rename), a runtime warning when an in-place change is detected, and an updater that only renames. | Registry unit test; updater test |
| An attacker with write access replaces a database. | Outside the plugin's control. Mount databases read-only for Kong, keep the updater the only writer, verify checksums and signatures. | Updater verifies `checksum.txt` and, when configured, the signature |
| Request floods make lookups expensive. | Work per request is bounded and independent of request content apart from header enumeration, which nginx limits. No network calls, so no amplification. | Benchmarks; budgets in unit tests |
| Block reasons leak policy details. | Clients receive only the configured message; reasons go to logs, the log serializer and, in dry run, an upstream header. | Unit and end-to-end tests |
| Configuration sets dangerous headers or paths. | The schema rejects relative paths, `..`, invalid header names and headers such as `Host`, `Content-Length`, `Authorization` and `Cookie`, and bounds every value. | Schema specs |
| Unset options arrive as `ngx.null` and break comparisons. | Every option is type-checked; null means unset. | Unit regression test |

## Residual risks

- **Misconfigured trusted proxies.** If `trusted_ips` includes untrusted networks, clients choose the
  address that is looked up. This is Kong configuration and cannot be detected by the plugin.
- **Fail-open windows.** With the default `fail_open: true`, a database that is missing (for example
  before the first download) means no blocking. Use `fail_open: false` on routes where blocking must never
  lapse.
- **In-place modification by other tools.** The plugin warns, but a crash can occur before the next check.
- **Personal data in logs.** IP addresses and derived data are personal data in many jurisdictions. Block
  logs contain the address; `log_serialize` (off by default) adds the resolved fields.
- **Data quality.** Decisions are only as accurate as the databases. Use dry run and exemptions to manage
  false positives.

## Operator checklist

- Set `trusted_ips` to your load balancers only, with `real_ip_recursive = on` behind `X-Forwarded-For`.
- Mount database directories read-only for Kong; let one updater write them, atomically.
- Verify `checksum.txt` and, where available, the archive signature.
- Use `fail_open: false` on routes whose protection must not lapse, and keep the default elsewhere.
- Roll out policies with `dry_run` first.
- Restrict who can change plugin configuration (Admin API access, RBAC, control plane).
- Review log retention for IP addresses.
