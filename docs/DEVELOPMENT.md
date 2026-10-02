# Development

## Layout

```
kong/plugins/ipgeolocation/   the plugin, flat (one directory, one ConfigMap)
spec/unit/                    unit tests: busted with PDK mocks, no Kong needed
spec/integration/             Kong test-harness specs, run with Pongo
spec/e2e/e2e.py               end-to-end tests against a real Kong
spec/ipgeolocation/           test support: MMDB writer, fixtures, helpers, PDK mock
bench/                        benchmarks
tools/                        cross-check, dump, validation and documentation generators
examples/                     DB-less, Docker, Kubernetes, database updater
docs/                         reference documentation
```

| Module | Responsibility |
|---|---|
| `mmdb.lua` | MaxMind DB reader: `open` (validate metadata, tree and separator), `lookup` (search tree), `extract` (single-pass projection of the needed paths), `record` (full decode, for tools and tests), `close`. Bounds-checked on every access; pointer, depth and work limits. |
| `iputil.lua` | IP parsing (IPv4, every IPv6 notation, zone IDs), IPv4-mapped normalisation, private-address classification, CIDR matching. |
| `fields.lua` | The field catalog: 85 fields with kinds and candidate paths, the presets, header naming. |
| `plan.lua` | Compiles a configuration once into a plan: the fields to resolve, a trie of their paths, the header map, the compiled policy. Cached per configuration table. |
| `resolver.lua` | Runs the lookups across databases and merges values into typed values and header strings. |
| `policy.lua` | Compiles and evaluates the rules. |
| `headers.lua` | Namespace stripping, sanitisation, header writing. |
| `registry.lua` | Per-worker database registry: loading, sharing, retry, validated refresh. |
| `handler.lua` | Kong handler: `configure`, `rewrite`, `access`. |
| `schema.lua` | Kong configuration schema. |

The request path is `handler.lua` →
`headers.lua` (strip) → `resolver.lua` (which uses `registry.lua` and `mmdb.lua`) → `headers.lua` (apply)
→ `policy.lua`. Configuration is compiled once by `plan.lua`.

## Tests

### Unit tests

```sh
busted            # .busted runs spec/unit
```

Requirements: LuaJIT 2.1 with FFI (OpenResty's), `busted` 2.2 and `luafilesystem`. The tests use
`spec/ipgeolocation/kong_mock.lua`, which models upstream request headers the way nginx exposes them
(lower-cased names, case-insensitive set and clear, `get_headers()` reflecting earlier changes) and asserts
that headers are enumerated without a limit.

### Integration tests

```sh
pongo run spec/integration                                   # Kong Gateway OSS 3.9 by default
KONG_VERSION=3.10.0.x KONG_LICENSE_DATA=... pongo run spec/integration
```

The specs run against PostgreSQL and DB-less (`strategy` `postgres` and `off`). Without Pongo, run them
with Kong's own `bin/busted` from a Kong source checkout at the matching tag: create the PostgreSQL user
and database from Kong's `spec/kong_tests.conf` (user `kong`, database `kong_tests`), and set
`KONG_LUA_PACKAGE_PATH` and `LUA_PATH` to include this repository.

### End-to-end tests

```sh
python3 spec/e2e/e2e.py              # about a minute
E2E_SLOW=1 python3 spec/e2e/e2e.py   # adds the refresh-without-reload check (80 more seconds)
```

Requires `kong` and `resty` on `PATH` (a Kong package installation) and free ports 18000, 18001 and 18999.
The script generates fixtures, starts an echo upstream and Kong with two workers, and stops everything at
the end. Kong's workers run as the unprivileged `nginx_user`, so everything they read must be readable by
that user; the script prepares its working directory accordingly.

Without a local Kong installation, run the suite in the official Kong image. Bypass the image's
entrypoint with `--entrypoint sh`: it exports `KONG_NGINX_DAEMON=off` for every command, so nginx stays
in the foreground and the script's `kong start` never returns. Copy the repository inside the container so
that no root-owned files are written to your checkout:

```sh
docker run --rm -u root --entrypoint sh -e E2E_SLOW=1 -v "$PWD":/src:ro kong:3.9 -c \
  'apt-get update -qq && apt-get install -y -qq python3 >/dev/null &&
   cp -r /src /plugin && cd /plugin && python3 spec/e2e/e2e.py'
```

### Fixtures

`spec/ipgeolocation/mmdb_writer.lua` is a small test-only MMDB writer: 24, 28 and 32-bit records, IPv4 and
IPv6 trees, pointer deduplication, `::ffff:0:0/96` aliasing, explicit types (`W.uint16`, `W.double`,
`W.array`, ...), crafted bytes for invalid-data tests (`W.raw`, `W.pointer`) and sparse padding to push
offsets past 2^31. Its output was verified with `python-maxminddb`.

`spec/ipgeolocation/fixtures.lua` builds databases shaped like the IPGeolocation.io releases, using only
documentation address space and AS numbers. To build them by hand:

```sh
resty -I . -e 'for k, v in pairs(require("spec.ipgeolocation.fixtures").build_all("/tmp/fx")) do print(k, v) end'
```

### Differential testing against python-maxminddb

```sh
pip install maxminddb
python3 tools/crosscheck.py <database.mmdb> [samples=2000] [seed=1]
```

Run it on IPGeolocation.io's databases and on MaxMind's conformance files (`test-data/` in the MaxMind-DB
repository) whenever `mmdb.lua` changes. The CI `crosscheck` job does this for the databases listed in the
`IPGEO_CROSSCHECK_URLS` repository secret, space-separated download links. The job is skipped when the
secret is not set. `tools/mmdb-dump.lua` is the Lua side of the comparison; `tools/mmdb-check.lua`
validates files with the plugin's reader.

## Benchmarks

```sh
python3 bench/sample-ips.py <location.mmdb> /tmp/bench-ips 20000
resty -I . bench/bench.lua <location.mmdb> <asn.mmdb> <security.mmdb> /tmp/bench-ips
```

`BENCH_N` sets the iterations (default 200,000). For in-gateway numbers, compare a route answered by
`request-termination` with the same route plus the plugin, using a load generator with keep-alive, and
convert the throughput difference into CPU per request.

## Generated documentation

```sh
resty -I . tools/gen-fields-doc.lua > docs/FIELDS.md
python3 tools/sample-hits.py <samples-dir> 400 > /tmp/hits.json
resty -I . tools/sample-matrix.lua /tmp/hits.json   # the table in docs/DATABASES.md
```

Regenerate `docs/FIELDS.md` whenever `fields.lua` changes.

## Releasing

1. Move the "Unreleased" entries in `CHANGELOG.md` under the new version.
2. Update the version in `handler.lua` (`VERSION`), `mmdb.lua` (`_VERSION`) and the rockspec (file name,
   `version`, `source.tag`).
3. Make sure CI is green, including the Enterprise jobs (they need the `KONG_LICENSE_DATA` secret).
4. Tag `vX.Y.Z`, attach the packed rock from the `package` job, and upload it to LuaRocks
   (`luarocks upload <rockspec> --api-key=...`).
