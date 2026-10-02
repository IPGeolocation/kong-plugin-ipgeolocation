# Kong IP Geolocation Plugin for IPGeolocation.io

Geo-blocking, VPN and proxy detection, and IP intelligence headers for Kong Gateway, powered by [IPGeolocation.io](https://ipgeolocation.io) MMDB databases. The plugin reads the databases from local disk and answers every lookup inside Kong's worker processes, with no API calls and no per-request cost.

Use it to block traffic by country, stop Tor exit nodes, VPNs, proxies and known attackers before they reach your services, route visitors by region, and add country, city, ASN and threat data to upstream requests and access logs.

```yaml
# Block Tor and known attackers on /login, and tell every backend where visitors are
plugins:
  - name: ipgeolocation
    route: login
    config:
      databases:
        - /usr/local/share/ipgeolocation/db-ip-location.mmdb
        - /usr/local/share/ipgeolocation/db-ip-security.mmdb
      headers:
        preset: standard
      policy:
        block_tor: true
        block_known_attacker: true
        block_threat_score_above: 80
```

**Jump to:** [Installation](#installation) | [Quick start](#quick-start) | [Databases](#getting-the-databases) | [Configuration](#configuration-reference) | [Headers](#request-headers) | [Security policy](#security-policy) | [Client IP](#client-ip-selection) | [Updates](#keeping-databases-up-to-date) | [Troubleshooting](#troubleshooting) | [FAQ](#frequently-asked-questions)

## Why use this plugin

Most Kong geolocation setups either call a remote API on every request or need a custom Kong build with a GeoIP library compiled in. This plugin ships as plain Lua, loads IPGeolocation.io databases once per worker, and answers each lookup locally in microseconds ([benchmarks](#performance-and-memory)).

- No API calls and no per-request billing. Every lookup is a read from a local file.
- Nothing to compile. The MMDB reader is pure LuaJIT, so it runs on a stock Kong Gateway with no `libmaxminddb`, Redis or extra Lua rocks.
- Decisions at the edge. Block or route in Kong before the request reaches authentication or your upstream.
- One plugin, many databases. Location, Security, Company, ASN, Abuse Contact, Hosting and Residential Proxy all load through one list, and the plugin [layers them](#how-it-works).
- Headers your backend can trust. The plugin removes every client supplied `X-IPGeo-*` header before it adds its own.
- Kong native. Global, Service and Route scopes, DB-less, PostgreSQL and hybrid mode, `KongPlugin` and `KongClusterPlugin`.
- The same field names, header names and presets as the IPGeolocation.io [Nginx module](https://github.com/IPGeolocation/ngx_http_ipgeolocation_module) and [Traefik plugin](https://github.com/IPGeolocation/traefik-plugin-ipgeolocation), so a backend sees the same headers whichever gateway sits in front of it.

## How it works

You list one or more `.mmdb` files under [`databases`](#configuration-reference). Kong opens each file in every worker when the configuration loads, then for every request the plugin:

1. Takes the client address that Kong's own trusted proxy handling produced (see [Client IP selection](#client-ip-selection)).
2. Removes any `X-IPGeo-*` header the client sent, so it cannot fake its location or reputation.
3. Looks the address up in each database, in the order you listed them.
4. For each field, takes the value from the first database that has it. List order is priority order.
5. Sets the [headers](#request-headers) you asked for, shares the result with [other plugins](#using-the-results-in-other-plugins), evaluates the [policy](#security-policy), then forwards or blocks.

Because the first match wins, databases layer: load a Location and a Security database together, and `country_code` comes from the first while `is_vpn` comes from the second.

The files are memory mapped. The kernel shares the mapped pages between all workers, and only the pages that lookups touch are read from disk.

## Requirements

- Kong Gateway 3.x on Linux. Tested end to end on Kong Gateway OSS 3.9.3 (DB-less) and with Kong's test harness on 3.9.2 against PostgreSQL and DB-less. Kong Gateway 3.10 LTS and 3.14 LTS use the same plugin APIs and are expected to work, but have not been tested yet.
- One or more IPGeolocation.io [`.mmdb` databases](#getting-the-databases).
- Read access to the database files for Kong's worker user (`kong` in the official packages and images), including every directory above them.

## Installation

Install the plugin on every Kong node that runs it. In hybrid mode that includes the control planes, which validate the configuration. Only the data planes need the database files.

### Install with LuaRocks

```sh
git clone https://github.com/IPGeolocation/kong-plugin-ipgeolocation.git
cd kong-plugin-ipgeolocation
luarocks make kong-plugin-ipgeolocation-0.1.0-1.rockspec
```

### Install in a Docker image

Build an image with the plugin baked in from [`examples/docker/Dockerfile`](examples/docker/Dockerfile):

```sh
docker build -f examples/docker/Dockerfile -t kong-ipgeolocation .
```

[`examples/docker/docker-compose.yml`](examples/docker/docker-compose.yml) runs Kong in DB-less mode next to an updater container that downloads the databases into a shared volume.

### Install on Kubernetes

The plugin's modules live in one directory, so a single ConfigMap carries the whole plugin, and the `kong/kong` Helm chart loads it with `plugins.configMaps`:

```sh
kubectl create configmap kong-plugin-ipgeolocation -n kong --from-file=kong/plugins/ipgeolocation
```

[`examples/kubernetes`](examples/kubernetes) has Helm values with a database volume, an init container and an updater sidecar, plus `KongPlugin` and `KongClusterPlugin` resources and an annotated Ingress.

### Enable the plugin

Add the plugin to `kong.conf` and restart Kong:

```ini
plugins = bundled,ipgeolocation
```

Or set `KONG_PLUGINS=bundled,ipgeolocation` in the environment.

## Quick start

These examples use DB-less declarative configuration. The same settings work through the Admin API (`POST /plugins` with `name=ipgeolocation`) and as a Kubernetes `KongPlugin` resource.

### Add geolocation headers for your backend

```yaml
_format_version: "3.0"
services:
  - name: api
    url: http://api.internal:8080
    routes:
      - name: api
        paths: [/]
plugins:
  - name: ipgeolocation
    config:
      databases:
        - /usr/local/share/ipgeolocation/db-ip-location.mmdb
        - /usr/local/share/ipgeolocation/db-ip-asn.mmdb
      headers:
        preset: standard
```

The upstream then receives headers like these for a client in Lahore:

```http
X-IPGeo-Country-Code: PK
X-IPGeo-Country-Name: Pakistan
X-IPGeo-Continent-Code: AS
X-IPGeo-State-Code: PK-PB
X-IPGeo-City-Name: Lahore
X-IPGeo-Zip-Code: 54000
X-IPGeo-Latitude: 31.54972
X-IPGeo-Longitude: 74.34361
X-IPGeo-Time-Zone: Asia/Karachi
X-IPGeo-ASN: AS64500
X-IPGeo-Organization-Name: Example Telecom PK
```

### Block countries in Kong

Serve a service only in Germany, Austria and Switzerland, and answer everyone else with `451`:

```yaml
plugins:
  - name: ipgeolocation
    service: shop
    config:
      databases: [/usr/local/share/ipgeolocation/db-ip-country.mmdb]
      headers: { preset: none }
      policy:
        allowed_countries: [DE, AT, CH]
        allow_unknown: false
        status_code: 451
        message: This service is not available in your region
```

### Stop VPNs, proxies and attackers in front of a login page

```yaml
plugins:
  - name: ipgeolocation
    route: login
    config:
      databases: [/usr/local/share/ipgeolocation/db-ip-security.mmdb]
      headers: { preset: none }
      policy:
        block_tor: true
        block_vpn: true
        block_proxy: true
        block_residential_proxy: true
        block_known_attacker: true
        block_threat_score_above: 80
```

A blocked client receives `403` with Kong's standard error body (`{"message":"Access denied","request_id":"..."}`) and never reaches the service. The reason is logged but never sent to the client.

### Run Kong behind a load balancer

If Kong sits behind a load balancer at `10.0.0.0/8`, tell Kong to trust it so the plugin looks up the visitor and not the load balancer:

```ini
trusted_ips = 10.0.0.0/8
real_ip_header = X-Forwarded-For
real_ip_recursive = on
```

[`examples/kong.yml`](examples/kong.yml) is a larger example with per country routing, rate limiting per country, a dry run rollout and logging.

## Getting the databases

Download the `.mmdb` files from your [IPGeolocation.io account](https://app.ipgeolocation.io/signup) and point [`databases`](#configuration-reference) at them. Each database has a static download link that never changes, so the same link serves the first download and every update. The link contains your API key, so keep it in a secret and out of your Kong configuration.

| Database | File | What it adds |
| --- | --- | --- |
| [IP Geolocation](https://ipgeolocation.io/ip-geolocation-database.html) | `db-ip-location.mmdb` or `db-ip-city.mmdb` | country, state, district, city, postal code, coordinates, time zone, currency; the Advance tier adds accuracy radius, confidence and connection type |
| [Country](https://ipgeolocation.io/geo-standard-databases.html) | `db-ip-country.mmdb` | country, continent and currency, in a smaller file |
| [ISP](https://ipgeolocation.io/geo-standard-databases.html) | `db-ip-isp.mmdb` or `db-ip-city-isp.mmdb` | ISP, ASN and connection type, with country or full location |
| [IP Security](https://ipgeolocation.io/ip-security-database.html) | `db-ip-security.mmdb` | threat score, Tor, VPN, proxy, relay, residential proxy, bot, spam, attacker, cloud and corporate gateway flags |
| [IP Company](https://ipgeolocation.io/ip-company-database.html) | `db-ip-company.mmdb` | company or ISP name, domain and type |
| [IP to ASN](https://ipgeolocation.io/ip-asn-database.html) | `db-ip-asn.mmdb` | AS number, name, organization, type and domain; the Extended tier adds RIR, allocation, routes and peers |
| [IP Abuse Contact](https://ipgeolocation.io/ip-abuse-contact-database.html) | `db-ip-abuse.mmdb` | abuse email, phone, address, route and country |
| [Residential Proxy](https://ipgeolocation.io/residential-proxy-database.html) | `db-residential-proxy.mmdb` | residential proxy provider and last seen date |
| [IP Hosting](https://ipgeolocation.io/ip-hosting-database.html) | `db-ip-hosting.mmdb` | hosting provider name |

Combined products ship two files in one archive, for example City + Security as `db-ip-city.mmdb` and `db-ip-security.mmdb`. List both files. Some combined files hold several data sets in one file, such as `db-ip-city-company-asn.mmdb`.

Load only what you need. Fields from a database you did not load stay empty, so referencing them is safe. [docs/DATABASES.md](docs/DATABASES.md) lists every file, the products that ship it and the fields it provides. Tiers and bundles are on the [pricing page](https://ipgeolocation.io/db-pricing.html), and the [database documentation](https://ipgeolocation.io/documentation/databases.html) shows the full schemas.

> [!TIP]
> You can evaluate the plugin before buying anything. IPGeolocation.io offers sample databases that are real MMDB files covering part of the address space, so you can work through the whole [Quick start](#quick-start) with them. To read a file directly, use [mmdbio](https://github.com/IPGeolocation/mmdbio).

## Configuration reference

The plugin can be applied globally, to a Service or to a Route. It cannot be scoped to a Consumer, because it runs before authentication, when the consumer is not known yet. Supported protocols are `http`, `https`, `grpc` and `grpcs`.

### Databases

| Parameter | Type | Default | Description |
|---|---|---|---|
| `databases` | array of strings, required | | Absolute paths of 1 to 16 MMDB files, in priority order. For every field, the first database that has a non-empty value wins. Paths are checked for syntax only, so a control plane does not need the files. |
| `database_refresh_interval` | integer | `0` | Seconds between checks for updated files. `0` turns checks off; otherwise the minimum is `60`. A changed file is opened and validated before it replaces the one in service. See [Keeping databases up to date](#keeping-databases-up-to-date). |

### Headers

| Parameter | Type | Default | Description |
|---|---|---|---|
| `headers.preset` | string | `minimal` | Headers to add: `none`, `minimal`, `standard` or `full`. See [Request headers](#request-headers). |
| `headers.custom` | map | `{}` | Header name to field name, applied on top of the preset. Adds headers with any name (`X-Country: country_code`). An empty field name removes a header the preset added (`X-IPGeo-Latitude: ""`). Client supplied copies of custom headers are removed too. Field names are listed in [docs/FIELDS.md](docs/FIELDS.md). |
| `headers.boolean_format` | string | `true_false` | Booleans as `true`/`false` (the Traefik plugin's format) or `1`/`0` with `one_zero` (the Nginx module's format). |
| `headers.list_separator` | string | `,` | Separator for list values such as VPN provider names, 1 to 8 characters. |
| `headers.language` | string | `en` | Language of country, region, city, continent and currency names: `en`, `de`, `ru`, `ko`, `pt`, `ja`, `fa`, `fr`, `zh`, `es`, `cs` or `it`. Falls back to English where a translation is missing. |
| `headers.max_value_length` | integer | `1024` | Maximum header value length in bytes, 16 to 8192. Longer values are cut on a UTF-8 character boundary. |

### Policy

| Parameter | Type | Default | Description |
|---|---|---|---|
| `policy.allowed_countries` | array of strings | `[]` | Only these ISO 3166-1 alpha-2 country codes may pass. Cannot be combined with `blocked_countries`. |
| `policy.blocked_countries` | array of strings | `[]` | These country codes are blocked. |
| `policy.allowed_continents` | array of strings | `[]` | Only these continents may pass: `AF`, `AN`, `AS`, `EU`, `NA`, `OC`, `SA`. Cannot be combined with `blocked_continents`. |
| `policy.blocked_continents` | array of strings | `[]` | These continents are blocked. |
| `policy.allowed_asns` | array of strings | `[]` | Only these autonomous systems may pass (`AS15169` or `15169`). Cannot be combined with `blocked_asns`. |
| `policy.blocked_asns` | array of strings | `[]` | These autonomous systems are blocked. |
| `policy.block_tor` | boolean | `false` | Block Tor exit nodes (`is_tor`). |
| `policy.block_vpn` | boolean | `false` | Block VPN endpoints (`is_vpn`). |
| `policy.block_proxy` | boolean | `false` | Block proxies (`is_proxy`). |
| `policy.block_relay` | boolean | `false` | Block privacy relays such as iCloud Private Relay (`is_relay`). |
| `policy.block_residential_proxy` | boolean | `false` | Block residential proxies (`is_residential_proxy`, from the Security or Residential Proxy database). |
| `policy.block_anonymous` | boolean | `false` | Block any anonymizing service (`is_anonymous`). |
| `policy.block_known_attacker` | boolean | `false` | Block known attackers (`is_known_attacker`). |
| `policy.block_bot` | boolean | `false` | Block bots (`is_bot`). Known good bots such as search engine crawlers are spared. |
| `policy.block_known_good_bots` | boolean | `false` | Make `block_bot` apply to known good bots as well. |
| `policy.block_spam` | boolean | `false` | Block known spam sources (`is_spam`). |
| `policy.block_cloud_provider` | boolean | `false` | Block cloud and hosting provider addresses (`is_cloud_provider`, from the Security or Hosting database). |
| `policy.block_corporate_gateway` | boolean | `false` | Block corporate egress gateways such as secure web gateways (`is_corporate_gateway`). |
| `policy.block_threat_score_above` | integer | unset | Block when `threat_score` (0 to 100, higher is riskier) is greater than this value. |
| `policy.exempt_ips` | array of strings | `[]` | Addresses or CIDRs that skip every policy rule. They are still enriched. To deny addresses, use Kong's `ip-restriction` plugin. |
| `policy.allow_private` | boolean | `true` | Pass private, loopback and link-local clients without a lookup and without headers. |
| `policy.allow_unknown` | boolean | `true` | For allow lists only: let a request pass when its country, continent or ASN is not in the databases. While a database is unavailable and `fail_open` is `true`, unknown values always pass. |
| `policy.fail_open` | boolean | `true` | When a database is missing, unreadable or corrupt, or the client address cannot be parsed, allow the request (`true`) or block it (`false`). |
| `policy.dry_run` | boolean | `false` | Evaluate and log the policy but never block. Adds `X-IPGeo-Dry-Run` with the reason to the upstream request. |
| `policy.status_code` | integer | `403` | Status code for blocked requests, 400 to 599. For example `451` for legal geo restrictions. |
| `policy.message` | string | `Access denied` | Message for blocked requests. The reason is never shown to the client. |

### Logging

| Parameter | Type | Default | Description |
|---|---|---|---|
| `log_serialize` | boolean | `false` | Add the lookup result and policy decision to Kong's log serializer under `ipgeolocation`, for http-log, file-log, tcp-log and similar plugins. |

Validation rejects relative paths, `..` segments, refresh intervals between 1 and 59 seconds, unknown presets and fields, invalid header names, headers the plugin must not set (`Host`, `Content-Length`, `Authorization`, `Cookie` and other hop-by-hop or framing headers), malformed country codes, continents, ASNs and CIDRs, combined allow and block lists, and status codes outside 400 to 599.

## Request headers

Header names are `X-IPGeo-` followed by the field name in title case, with common acronyms in capitals. `country_code` becomes `X-IPGeo-Country-Code`, `is_vpn` becomes `X-IPGeo-Is-VPN` and `asn` becomes `X-IPGeo-ASN`. These are the headers the Traefik plugin sets.

| Preset | Headers |
|---|---|
| `none` | none. Use `headers.custom`, or only enforce the policy. |
| `minimal` | `X-IPGeo-Country-Code`, `X-IPGeo-City-Name`, `X-IPGeo-ASN` |
| `standard` | country code and name, continent code, state code, city, zip code, latitude, longitude, time zone, ASN, organization name, threat score, `X-IPGeo-Is-VPN`, `X-IPGeo-Is-Proxy`, `X-IPGeo-Is-Tor` |
| `full` | all 81 bounded fields plus `X-IPGeo-IP`, the address that was looked up |

`full` leaves out the ASN routing lists (`asn_routes`, `asn_peers`, `asn_upstreams`, `asn_downstreams`), which can hold thousands of entries. Map them with `headers.custom` if you need them. All 85 fields, their headers and the database paths they are read from are in [docs/FIELDS.md](docs/FIELDS.md).

### How values are formatted

- Missing data means no header. A field the databases do not have, or have as an empty string, is not sent, and a header is never sent with an empty value. An address without a record in the Security Database is not flagged, so its security headers are absent and not `false`.
- Booleans are `true`/`false` or `1`/`0`, set by `headers.boolean_format`, whatever the database stores.
- Numbers keep the database's own text (`31.54972`), so values match the Nginx and Traefik integrations.
- ASNs are written as `AS64500`. The `asn_number` field gives the bare number.
- Lists are joined with `headers.list_separator`.
- Control characters, including CR and LF, are removed, and values are capped at `headers.max_value_length`, so database content can never inject headers.

### Spoofed header protection

Before it adds anything, the plugin removes every request header whose name starts with `X-IPGeo-`, in any letter case and also when written with underscores (`X_IPGeo_Country_Code`, which some backend frameworks treat as the same name). Headers mapped in `headers.custom` are removed the same way, and all request headers are examined however many the client sends. This happens on every request the plugin handles, including private and exempt clients. A client that sends `X-IPGeo-Country-Code: US` from Pakistan reaches the backend as `PK`.

## Security policy

Rules are evaluated in a fixed order, and the first rule that blocks decides:

1. countries (`allowed_countries` or `blocked_countries`)
2. continents (`allowed_continents` or `blocked_continents`)
3. autonomous systems (`allowed_asns` or `blocked_asns`)
4. security flags, in the order of the [policy table](#policy)
5. threat score (`block_threat_score_above`)

How the plugin treats missing data:

- Block lists, flags and the threat score block only on positive evidence. The Security Database covers flagged ranges, so an address without a record is not flagged.
- Allow lists need a known value. When the country, continent or ASN is unknown, `allow_unknown` decides: pass by default, block when set to `false`.
- The threat score must be greater than the threshold. `block_threat_score_above: 80` blocks 81 and above, never 80.
- Known good bots are spared by `block_bot` unless `block_known_good_bots` is set.
- Exempt and private clients skip the policy (`exempt_ips`, `allow_private`).
- A missing or broken database is never treated as a reason to block. It follows [`fail_open`](#failure-handling).

Blocked requests receive `policy.status_code` with Kong's standard error body containing `policy.message`, formatted for the client's `Accept` header like Kong's other plugins. The reason is logged at `info` level and available to log plugins.

> [!TIP]
> Roll out a new policy with `dry_run: true` first. Nothing is blocked, requests that would be blocked carry `X-IPGeo-Dry-Run: <reason>` to the upstream, and Kong logs them at `notice` level. With `log_serialize: true` the decision also appears in your access logs, so you can measure the impact before you switch `dry_run` off.

## Client IP selection

The plugin looks up `kong.client.get_forwarded_ip()`, the client address after Kong's real IP processing. It never parses `X-Forwarded-For` itself. Configure Kong, not the plugin:

| Kong is behind | `kong.conf` |
|---|---|
| nothing, clients connect directly | nothing to configure |
| a load balancer that sets `X-Forwarded-For` | `trusted_ips = <load balancer addresses>`, `real_ip_header = X-Forwarded-For`, `real_ip_recursive = on` |
| a CDN that sends the client address in its own header, such as Cloudflare | `trusted_ips = <the CDN's published ranges>`, `real_ip_header = <that header>`, for example `CF-Connecting-IP` |
| a load balancer using the PROXY protocol | `proxy_listen = 0.0.0.0:8000 proxy_protocol`, `trusted_ips = <load balancer addresses>`, `real_ip_header = proxy_protocol` |

With `real_ip_recursive = on`, Kong walks `X-Forwarded-For` from the right and stops at the first address that is not trusted, so entries a client adds in front cannot change the result. IPv4-mapped IPv6 addresses such as `::ffff:203.0.113.7` are looked up as IPv4.

> [!IMPORTANT]
> Only list addresses you control in `trusted_ips`. Trusting everything (`0.0.0.0/0,::/0`) lets any client choose the address that is looked up, which defeats the security policy.

When `trusted_ips` is not set, Kong ignores `X-Forwarded-For` and uses the TCP peer. Behind a load balancer that peer is usually a private address, which the plugin skips by default (`allow_private`), so no headers appear. To check which address is being looked up, map the pseudo field `ip` to a header: `headers.custom: { X-IPGeo-IP: ip }`.

## Scopes, phases and routing

- Priority 2450. The plugin runs after `bot-detection` (2500) and before `cors` (2000), every authentication plugin and `ip-restriction` (990). Blocked requests never reach authentication or the upstream.
- Precedence. As with every Kong plugin, a Route instance overrides a Service instance, which overrides the global instance, and only one instance runs per request.
- Routing on enrichment. A global instance enriches in the `rewrite` phase, before Kong routes the request, so routes can match on its headers. A spoofed header cannot steer routing because it is replaced first. Route and Service instances run in the `access` phase, after routing. When one of them overrides a global instance, the headers the global instance set are removed and the more specific configuration applies.

Send German traffic to a dedicated service:

```yaml
routes:
  - name: de
    paths: [/shop]
    headers:
      x-ipgeo-country-code: [DE]
    service: shop-de
  - name: default
    paths: [/shop]
    service: shop
plugins:
  - name: ipgeolocation          # global: runs before routing
    config:
      databases: [/usr/local/share/ipgeolocation/db-ip-country.mmdb]
      headers: { preset: minimal }
```

## Using the results in other plugins

Plugins that run later (lower priority) can read the headers and the shared context:

```lua
local geo = kong.ctx.shared.ipgeolocation
-- geo.ip        the address that was looked up
-- geo.found     true when any database had a record
-- geo.private   true when the address was skipped as private
-- geo.exempt    true when the address matched exempt_ips
-- geo.fields    typed values: geo.fields.country_code == "PK", geo.fields.is_vpn == true,
--               geo.fields.threat_score == 60, geo.fields.vpn_provider == { "Nord VPN" }
-- geo.blocked, geo.dry_run, geo.reason   the policy decision
```

Treat it as read only. These combinations are covered by the end to end tests:

- Rate limiting per country: `rate-limiting` with `limit_by: header` and `header_name: X-IPGeo-Country-Code`.
- Renaming headers: `request-transformer`, for example `rename.headers: ["X-IPGeo-City-Name:X-City"]`.
- Custom logic: `post-function` or your own plugin reading `kong.ctx.shared.ipgeolocation`.
- Logging: with `log_serialize: true`, http-log, file-log, tcp-log, udp-log and syslog receive an `ipgeolocation` object with the address, the resolved fields and the policy decision.

Use `ip-restriction` for static address allow and deny lists. It runs after this plugin.

## Real world examples

### Keep hosting providers and bots off a public API

Search engine crawlers stay allowed, and a partner range is exempt:

```yaml
policy:
  block_cloud_provider: true
  block_bot: true
  exempt_ips: [198.51.100.0/24]
```

### Rate limit each country separately

```yaml
plugins:
  - name: ipgeolocation
    config:
      databases: [/usr/local/share/ipgeolocation/db-ip-country.mmdb]
      headers: { preset: minimal }
  - name: rate-limiting
    config:
      minute: 600
      limit_by: header
      header_name: X-IPGeo-Country-Code
```

### Enrich access logs for analytics and fraud review

```yaml
plugins:
  - name: ipgeolocation
    config:
      databases:
        - /usr/local/share/ipgeolocation/db-ip-location.mmdb
        - /usr/local/share/ipgeolocation/db-ip-security.mmdb
      headers: { preset: none }
      log_serialize: true
  - name: file-log
    config:
      path: /var/log/kong/requests.log
```

Each log entry then has an `ipgeolocation` object with the country, city, ASN, threat score and flags of the client.

## Keeping databases up to date

IPGeolocation.io updates its databases daily. [`examples/updater/ipgeolocation-update.sh`](examples/updater/ipgeolocation-update.sh) downloads them, checks `checksum.txt`, optionally checks IPGeolocation.io's signature with their public key, validates each file and installs it. Give it the download links through the `IPGEO_URLS` environment variable from a secret. It never writes the links' query strings, which hold your API key, to its log.

> [!IMPORTANT]
> Replace a database file atomically, never edit it in place. Download to a temporary file in the same directory, check it, then rename it over the old file. Truncating or rewriting a file that Kong has mapped can serve torn data or crash workers with `SIGBUS`. The updater script does this for you, and the plugin logs a warning when it sees a file modified in place.

There are two ways to make Kong use the new files:

- `kong reload`, the default. New workers open the new files and old workers finish their requests with the old ones. This works everywhere, including with refresh turned off. The updater runs it for you with `-r`.
- `database_refresh_interval`. Each worker checks the file at that interval and swaps in a validated replacement without a reload. If the replacement does not validate, the database in service stays. Workers swap independently, so for up to one interval plus 10 seconds different workers can serve different releases.

On Kubernetes, prefer storage local to the pod, such as an `emptyDir` filled by an init container and refreshed by a sidecar as in [`examples/kubernetes`](examples/kubernetes), or a rolling restart. Do not replace files on a network filesystem shared across nodes while Kong has them mapped, because a file replaced from another node can become a stale handle on the node that maps it.

## Failure handling

| Situation | Behavior |
|---|---|
| A database is missing or invalid at startup | Logged once per distinct error and retried every 30 seconds without blocking traffic. Requests follow `fail_open`. |
| One of several databases is unavailable | The others still enrich. With `fail_open: true` their values are still enforced and unknown values pass allow lists; with `false` the request is blocked. |
| A refresh finds an invalid replacement | The database in service stays and the error is logged. The same broken file is not retried until it changes. |
| A database is deleted while in use | The mapped copy keeps serving until the next reload or restart. |
| A database record is malformed | The lookup fails safely within bounds and work limits, and the request follows `fail_open`. |
| IPv6 client, IPv4 only database | No data from that database. This is not a failure. |
| The client address is not an IP address, for example a Unix socket | Follows `fail_open`. |
| The address is in no database | No headers. Allow lists consult `allow_unknown`, and nothing else blocks. |

With `fail_open: false`, a request is blocked whenever the plugin cannot reach a decision, and the reason recorded is `IP intelligence unavailable`. Unavailability is logged at most once a minute per worker.

## Performance and memory

Measured on one vCPU of an Intel Xeon at 2.1 GHz with IPGeolocation.io's sample databases (search trees of up to 9.5 million nodes) and LuaJIT 2.1 in OpenResty. Database work alone:

| Operation | Time |
|---|---|
| IPv4 / IPv6 search tree lookup | 0.78 µs / 1.91 µs |
| Location lookup, `minimal` preset fields | 3.2 µs |
| Location lookup, `standard` preset fields | 6.6 µs |
| Location lookup, every field | 12.3 µs |
| Security lookup, fields for a typical security policy | 3.3 µs |
| Location + ASN + Security, `standard` preset plus policy fields | 14.3 µs (IPv4), 22.2 µs (IPv6) |

Inside Kong (one worker, `ab` on the same vCPU, Kong answering directly with `request-termination` at about 40,000 requests per second), the plugin adds this much CPU per request:

| Configuration | Added CPU per request |
|---|---|
| Security policy only, no headers, 1 database | 15 µs |
| `minimal` preset, Location + ASN | 21 µs |
| `standard` preset, Location + ASN + Security, with or without policy | 33 µs |

About half of the `standard` figure is database work, a fifth is setting 15 headers, and the rest is header stripping and Kong's own per plugin work. To keep the cost down, request only the headers your services use, and use `preset: none` where you only need the policy.

Opening 305 MiB of databases added 1.2 MiB of resident memory. Pages are read on demand and shared by all workers through the page cache, so plan for the page cache to hold the parts of your databases that traffic touches. For heavy and varied traffic that can be their full size, and the full Security Database is several GiB. [`bench/bench.lua`](bench/bench.lua) reproduces the database measurements on your own databases and hardware.

## Troubleshooting

**Log says `database ... is unavailable: ...Permission denied`.** Kong's worker user (`kong`) cannot read the file or a directory above it. Fix the ownership or modes, then wait 30 seconds or run `kong reload`.

**No `X-IPGeo-*` headers at all.** The address being looked up is private, usually your load balancer's. Configure `trusted_ips` and `real_ip_header` as described in [Client IP selection](#client-ip-selection), and map `ip` to a header to see the address.

**Every request gets the same location.** Same cause: Kong sees the load balancer and not the client.

**One header is missing.** The databases you loaded have no value for that field, or the value is empty for that address. [docs/DATABASES.md](docs/DATABASES.md) lists the fields of every database file. To inspect a record directly, use [mmdbio](https://github.com/IPGeolocation/mmdbio).

**An updated database is not used.** Refresh is off by default. Run `kong reload`, or set `database_refresh_interval`.

**Log says `... was modified in place`, or workers exit with signal 7 (`SIGBUS`) after an update.** Your update process rewrites the file. Download to a temporary file in the same directory and rename it, as described in [Keeping databases up to date](#keeping-databases-up-to-date).

**`schema violation` on a path.** Paths must be absolute file paths without `..`. Kong does not check that the file exists when it validates the configuration.

**Everything is blocked, or nothing is.** Turn on `dry_run` and read the reasons in the log. `allow_private` skips internal traffic, and `allow_unknown` decides what happens to addresses that no database covers.

**`block_bot` lets Googlebot through.** This is by design. Crawlers are flagged as bots and as known good bots, and blocking them removes you from search results. Set `block_known_good_bots: true` if you really want them blocked.

## Frequently asked questions

<details>
<summary><strong>Does this plugin call the IPGeolocation.io API?</strong></summary>

No. It reads local `.mmdb` files and makes no outbound requests on the request path, so there are no API quotas and no per-request costs, and Kong keeps working if the network to IPGeolocation.io is down. Only the [updater](#keeping-databases-up-to-date) talks to IPGeolocation.io, to download new releases.

</details>

<details>
<summary><strong>Which databases do I need?</strong></summary>

It depends on what you block or send to your backend. Country and city headers or geo-blocking need the IP Geolocation database, or the smaller Country database for country rules only. VPN, proxy, Tor, bot and threat score rules need the Security Database. ASN filtering needs IP to ASN, and ISP or company names need IP Company. You can load several together and the plugin [layers them](#how-it-works), so start with one and add more later without changing your rules. The full list is in [Getting the databases](#getting-the-databases).

</details>

<details>
<summary><strong>How is this different from other Kong GeoIP plugins?</strong></summary>

Most use `libmaxminddb` through FFI or need a custom Kong or OpenResty build with an nginx GeoIP module. This plugin has its own MMDB reader in pure LuaJIT, so it installs on a stock Kong with LuaRocks or a ConfigMap. It is built for IPGeolocation.io schemas, [layers multiple databases](#how-it-works), exposes [security and ASN data](#request-headers) as well as location, and can block on any of it.

</details>

<details>
<summary><strong>Does it work with DB-less mode, PostgreSQL, hybrid mode and Kubernetes?</strong></summary>

Yes. The plugin is tested in DB-less mode and with PostgreSQL. In hybrid mode, install it on the control planes and the data planes, and put the database files on the data planes only. On Kubernetes, load it with a ConfigMap through the `kong/kong` Helm chart and configure it with `KongPlugin` or `KongClusterPlugin`. See [Installation](#installation).

</details>

<details>
<summary><strong>Can I route requests by country?</strong></summary>

Yes. Apply the plugin globally so it runs before Kong's router, then match routes on the `X-IPGeo-Country-Code` header. A client cannot steer routing with a fake header, because the plugin replaces it first. See [Scopes, phases and routing](#scopes-phases-and-routing).

</details>

<details>
<summary><strong>Can clients fake the X-IPGeo headers?</strong></summary>

No. The plugin removes every client supplied header in the `X-IPGeo-` namespace, in any letter case and with underscores, before it adds its own. It also removes client copies of your custom header names. See [Spoofed header protection](#spoofed-header-protection).

</details>

<details>
<summary><strong>Does it work behind Cloudflare, an AWS load balancer or another proxy?</strong></summary>

Yes. Set Kong's `trusted_ips` to the proxy's addresses and `real_ip_header` to the header that carries the client address, such as `X-Forwarded-For` or `CF-Connecting-IP`. Without that, every visitor looks like your load balancer. See [Client IP selection](#client-ip-selection).

</details>

<details>
<summary><strong>How much latency does it add?</strong></summary>

About 15 µs of CPU per request for a security policy without headers, and about 33 µs with the `standard` preset across three databases. Cost grows with the number of headers and rules you use, not with the size of the database. The numbers and the benchmark setup are in [Performance and memory](#performance-and-memory).

</details>

<details>
<summary><strong>How do I update the databases without restarting Kong?</strong></summary>

Set `database_refresh_interval` (for example `3600`) and have a scheduled job replace the files atomically. The plugin notices the change, validates the new file, swaps it in and keeps serving the old copy if the new one does not open. You can also run `kong reload` after each update. See [Keeping databases up to date](#keeping-databases-up-to-date).

</details>

<details>
<summary><strong>What happens if a database is missing or broken?</strong></summary>

Traffic keeps flowing by default. A missing database is retried every 30 seconds, a broken replacement never replaces the database in service, and requests follow `fail_open`, which allows them unless you set it to `false`. See [Failure handling](#failure-handling).

</details>

<details>
<summary><strong>Does it support IPv6?</strong></summary>

Yes. IPGeolocation.io databases cover both address families, and the plugin looks up whichever address Kong resolved for the client. Every rule and header works the same for IPv6, and IPv4-mapped addresses such as `::ffff:203.0.113.7` are looked up as IPv4.

</details>

<details>
<summary><strong>Can I use the same databases with Nginx and Traefik?</strong></summary>

Yes. The [Nginx module](https://github.com/IPGeolocation/ngx_http_ipgeolocation_module) and the [Traefik plugin](https://github.com/IPGeolocation/traefik-plugin-ipgeolocation) read the same files and use the same field names, header names and presets. The Kong plugin always strips the whole `X-IPGeo-` namespace, always takes the client address from Kong's trusted proxy handling, and leaves the long ASN routing lists out of the `full` preset. Dry run, exemptions, a configurable status code and message, and log integration are Kong additions.

</details>

## Development

```sh
luacheck .                       # lint
busted                           # unit tests (spec/unit), no Kong needed
pongo run spec/integration       # Kong's test harness: schema and proxy behavior, PostgreSQL and DB-less
python3 spec/e2e/e2e.py          # a real Kong (kong and resty on PATH), end to end
```

[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) covers the code layout, the test fixtures, the cross check against `python-maxminddb`, benchmarks and the release process. Contributions are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities as described in [SECURITY.md](SECURITY.md), and read [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) for the threat model.

## Related tools and links

IPGeolocation.io tools:

- [Nginx module](https://github.com/IPGeolocation/ngx_http_ipgeolocation_module), the same databases as native nginx variables ([documentation](https://ipgeolocation.io/documentation/nginx-integration))
- [Traefik plugin](https://github.com/IPGeolocation/traefik-plugin-ipgeolocation), the same databases as a Traefik middleware
- [mmdbio](https://github.com/IPGeolocation/mmdbio), a command line tool for reading and inspecting MMDB files
- [IPGeolocation CLI](https://github.com/IPGeolocation/cli), IP intelligence from your terminal and shell scripts
- [Integration guides](https://github.com/IPGeolocation/ipgeolocation-guides), setup guides for every integration
- [All repositories](https://github.com/IPGeolocation)

Account, data and support:

- [Sign up for a free account](https://app.ipgeolocation.io/signup)
- [Database documentation and schemas](https://ipgeolocation.io/documentation/databases.html)
- [Database pricing and bundles](https://ipgeolocation.io/db-pricing.html)
- [IP geolocation API or database: which one to use](https://ipgeolocation.io/guides/ip-geolocation-api-vs-database-guide)
- [What is IP geolocation and how does it work](https://ipgeolocation.io/guides/what-is-ip-geolocation-how-it-works)
- [Contact support](https://ipgeolocation.io/contact.html)
- [Service status](https://status.ipgeolocation.io)

Kong and format references:

- [Kong Gateway documentation](https://developer.konghq.com/gateway/)
- [Kong Pongo](https://github.com/Kong/kong-pongo), the plugin test harness used by this repository
- [MaxMind DB file format specification](https://maxmind.github.io/MaxMind-DB/)

## License

MIT. See [LICENSE](LICENSE).

Built for [IPGeolocation.io](https://ipgeolocation.io) databases. Questions about the data, tiers or bundles are answered on the [database documentation](https://ipgeolocation.io/documentation/databases.html) and [pricing](https://ipgeolocation.io/db-pricing.html) pages.
