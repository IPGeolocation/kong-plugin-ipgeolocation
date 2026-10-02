# IPGeolocation.io databases

## Archives, checksums and signatures

IPGeolocation.io delivers each MMDB database as a ZIP archive containing three files: the `.mmdb`
database, a `README.md`, and `checksum.txt` with SHA-256 checksums of the other two:

```sh
unzip db-ip-security.zip -d release
cd release && sha256sum -c checksum.txt     # prints "<file>: OK" for each file
```

Each release also has a signature over the archive, made with IPGeolocation.io's private key. With their
public key saved as `public-key.pem`:

```sh
openssl dgst -sha256 -verify public-key.pem -signature db-ip-security.zip.sig db-ip-security.zip
# Verified OK
```

The checksum proves integrity; the signature proves integrity and origin.
[`examples/updater/ipgeolocation-update.sh`](../examples/updater/ipgeolocation-update.sh) performs both
(signature verification when given the key and signature) before installing a file atomically.

## Download links

Each database in your IPGeolocation.io account has a static download link that does not change, so the
same link serves the first download and every update. The link contains your API key. Keep it in a
secret store or an environment variable, never in `kong.yml`, a Kubernetes manifest or a public
repository.

IPGeolocation.io also offers sample databases for evaluation. They are real MMDB files that cover part of
the address space, and they work with the plugin exactly like the full databases.

## Database files

Every IPGeolocation.io MMDB product, the IP WHOIS database excepted, was tested with the plugin using the
official samples built on 2026-09-30. For each file the plugin's reader was compared with
`python-maxminddb` on about 8,000 addresses spread over IPv4 and IPv6, every field was resolved and
compared with an independent decoding of the same record (in English, German and Chinese), and the files
were run through Kong with header and policy checks.

A product download is a ZIP archive with one or two `.mmdb` files. List every file of the archive in
`databases`. Products that combine data ship separate files, for example City + Security as
`db-ip-city.mmdb` and `db-ip-security.mmdb`.

| File | Shipped in | Fields |
|---|---|---|
| `db-ip-country.mmdb` | Country | `country_code`, `country_code3`, `country_code_ioc`, `country_name`, `country_name_official`, `country_capital`, `continent_code`, `continent_name`, `currency_code`, `currency_name`, `currency_symbol`, `calling_code`, `languages`, `tld` |
| `db-ip-location.mmdb` (Standard), `db-ip-city.mmdb` | Location (Standard); City + Security | the Country fields, plus `state_code`, `state_name`, `district_name`, `city_name`, `zip_code`, `latitude`, `longitude`, `geoname_id`, `time_zone` |
| `db-ip-location.mmdb` (Advance) | Location (Advance) | the Standard Location fields, plus `accuracy_radius`, `confidence`, `dma_code`, `connection_type` |
| `db-ip-isp.mmdb` | ISP | the Country fields, plus `connection_type`, `company_name`, `isp_name`, `asn`, `asn_number`, `asn_organization`, `asn_country` |
| `db-ip-city-isp.mmdb` | City + ISP; City + ISP + Security | the Standard Location fields, plus `connection_type`, `company_name`, `isp_name`, `asn`, `asn_number`, `asn_organization`, `asn_country` |
| `db-ip-asn.mmdb` | ASN | `asn`, `asn_number`, `asn_organization`, `asn_country`, `asn_domain`, `asn_type`, `organization_name` |
| `db-ip-asn.mmdb` | ASN Extended | the ASN fields, plus `asn_name`, `asn_rir`, `asn_date_allocated`, `asn_allocation_status`, `asn_routes`, `asn_peers`, `asn_upstreams`, `asn_downstreams` |
| `db-ip-company.mmdb` | Company | `company_name`, `company_domain`, `company_type`, `isp_name`, `organization_name` |
| `db-ip-company-asn.mmdb` | Company + ASN | the Company and ASN fields |
| `db-ip-city-company-asn.mmdb` | City + Company + ASN; City + Company + ASN + Security | the Advance Location, Company and ASN fields; some releases also carry the ASN Extended fields |
| `db-ip-city-company-asn-abuse.mmdb` | City + Company + ASN + Abuse; City + Company + ASN + Abuse + Security | the Advance Location, Company, ASN and Abuse fields |
| `db-ip-abuse.mmdb` | Abuse Contact | `abuse_name`, `abuse_email`, `abuse_phone`, `abuse_address`, `abuse_country_code`, `abuse_kind`, `abuse_route` |
| `db-ip-security.mmdb` | Security Database, and every product that includes Security | `threat_score`, `is_tor`, `is_proxy`, `is_vpn`, `is_relay`, `is_residential_proxy`, `is_anonymous`, `is_known_attacker`, `is_bot`, `is_spam`, `is_cloud_provider`, `cloud_provider`, `proxy_provider`, `vpn_provider`, `relay_provider`, `proxy_confidence`, `vpn_confidence`, `proxy_last_seen`, `vpn_last_seen`, `is_known_good_bot`, `bot_type`, `bot_operator`, `bot_confidence`, `bot_last_seen`, `is_corporate_gateway`, `corporate_gateway_provider`, `corporate_gateway_type` |
| `db-ip-hosting.mmdb` | Hosting | `is_cloud_provider`, `hosting_provider` |
| `db-residential-proxy.mmdb` | Residential Proxy | `is_residential_proxy`, `proxy_provider`, `residential_proxy_provider`, `residential_proxy_last_seen` |

A field is listed when the file stores it. Some fields are empty in most records (for example
`relay_provider`, `bot_operator` and the corporate gateway details), so their headers appear only for the
addresses that have them.

Older Security Database files carry fewer fields. Some have no `is_vpn`, `is_relay`, confidence or
last-seen fields, and some have no `is_residential_proxy` flag. In those files the plugin derives
`is_residential_proxy` from the proxy provider name. On the samples this agreed with the current Security
Database for about 98% of addresses. Use a current Security Database file for residential proxy policy.

## Format notes

- All samples are MMDB format 2.0 with an IPv6 search tree and 32-bit records. IPv4 addresses are stored
  in the `::/96` subtree; whether `::ffff:0:0/96` is aliased to it differs between files, so the plugin
  looks up IPv4-mapped client addresses as IPv4.
- Security flags are the strings `"true"` and `"false"`; scores are integers. The plugin also accepts
  native booleans and numbers.
- Coordinates, accuracy radius and similar numbers are strings. Header values keep this text; the typed
  values exported to `kong.ctx.shared` are numbers.
- Names are maps of 12 languages (`en`, `de`, `ru`, `ko`, `pt`, `ja`, `fa`, `fr`, `zh`, `es`, `cs`, `it`).
  The metadata lists Chinese as `zh-CN`, the records as `zh`; the plugin uses the record keys.
- Empty strings mean "no data" and never produce a header.
- `db-ip-isp.mmdb` and `db-ip-city-isp.mmdb` keep ISP and ASN data flat (`asn`, `as_organization`, `isp`);
  the other files nest data under `location`, `asn`, `company` and `abuse`. The plugin also reads security
  data nested under `security`, a layout used by some older bundle files.
- The ASN Extended routing lists (`asn_routes`, `asn_peers`, `asn_upstreams`, `asn_downstreams`) are stored
  as comma-separated strings that can exceed 16 KiB. The plugin reads at most 16 KiB of any string, so
  the longest lists are cut, and the last item can be incomplete. These fields are not in any preset;
  header values are further limited by `headers.max_value_length`.
- A record that breaks the MMDB format (for example a pointer to another pointer, which the
  specification forbids) is not decoded. The lookup counts as a failure of that database and follows
  `policy.fail_open`; with `fail_open: false` such requests are blocked. The other databases still
  enrich the request.
- `database_type` is generic and does not identify the product; `description.en` does (for example
  `MAX-IP-GEO Database from ipgeolocation.io.`).

## Choosing and ordering databases

- Typical: `[location, asn, security]`, or every file of a combined product.
- Order matters only where databases overlap. `organization_name` prefers the company name and falls back
  to the ASN organisation in whichever database comes first; put `db-ip-company.mmdb` first if the company
  name should win.
- The Security Database alone is enough for a policy without headers (`headers.preset: none`).
- The Residential Proxy and Hosting databases flag addresses by presence: a record means
  `is_residential_proxy` or `is_cloud_provider` respectively, unless an earlier database states the flag.
  The current Security Database states both flags for every address it covers, so when it is listed first an
  address it marks `false` stays `false`. List the Residential Proxy or Hosting database first if its
  records should win.
- The IP WHOIS and ASN WHOIS databases are not supported.
