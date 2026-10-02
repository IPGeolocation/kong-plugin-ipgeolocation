# Field reference

Generated from `kong/plugins/ipgeolocation/fields.lua` by `tools/gen-fields-doc.lua`.

Each field can be sent upstream as a header (through a preset or `headers.custom`) and is
available to other plugins in `kong.ctx.shared.ipgeolocation.fields`. Database paths are
tried in order inside each database; across databases the first non-empty value wins.
`{lang}` is the configured `headers.language`, falling back to `en`.

"Smallest preset" is the smallest preset that includes the field (`minimal` is contained
in `standard`, which is contained in `full`). "custom only" fields must be mapped explicitly.


## Location

| Field | Header | Type | Smallest preset | Database paths |
|---|---|---|---|---|
| `country_code` | `X-IPGeo-Country-Code` | text | minimal | `location.country.code2`, `country.code2`, `location.country_code2`, `country_code2`, `country_code` |
| `country_code3` | `X-IPGeo-Country-Code3` | text | full | `location.country.code3`, `country.code3`, `location.country_code3`, `country_code3` |
| `country_code_ioc` | `X-IPGeo-Country-Code-IOC` | text | full | `location.country.code_ioc`, `country.code_ioc`, `country_code_ioc` |
| `country_name` | `X-IPGeo-Country-Name` | text | standard | `location.country.name`, `country.name`, `location.country_name`, `country_name` |
| `country_name_official` | `X-IPGeo-Country-Name-Official` | text | full | `location.country.name_official`, `country.name_official`, `location.country_name_official`, `country_name_official` |
| `country_capital` | `X-IPGeo-Country-Capital` | text | full | `location.country.capital`, `country.capital`, `location.country_capital`, `country_capital` |
| `is_eu` | `X-IPGeo-Is-EU` | boolean | full | `location.is_eu`, `is_eu` |
| `continent_code` | `X-IPGeo-Continent-Code` | text | standard | `location.country.continent.code`, `country.continent.code`, `location.continent_code`, `continent_code` |
| `continent_name` | `X-IPGeo-Continent-Name` | text | full | `location.country.continent.name`, `country.continent.name`, `location.continent_name`, `continent_name` |
| `currency_code` | `X-IPGeo-Currency-Code` | text | full | `location.country.currency.code`, `country.currency.code`, `currency.code`, `currency_code` |
| `currency_name` | `X-IPGeo-Currency-Name` | text | full | `location.country.currency.name`, `country.currency.name`, `currency.name`, `currency_name` |
| `currency_symbol` | `X-IPGeo-Currency-Symbol` | text | full | `location.country.currency.symbol`, `country.currency.symbol`, `currency.symbol`, `currency_symbol` |
| `calling_code` | `X-IPGeo-Calling-Code` | text | full | `location.country.metadata.calling_code`, `country.metadata.calling_code`, `country_metadata.calling_code`, `calling_code` |
| `languages` | `X-IPGeo-Languages` | list | full | `location.country.metadata.languages`, `country.metadata.languages`, `country_metadata.languages`, `languages` |
| `tld` | `X-IPGeo-TLD` | text | full | `location.country.metadata.tld`, `country.metadata.tld`, `country_metadata.tld`, `tld` |
| `state_code` | `X-IPGeo-State-Code` | text | standard | `location.state.code`, `state.code`, `location.state_code`, `state_code` |
| `state_name` | `X-IPGeo-State-Name` | text | full | `location.state.name`, `state.name`, `location.state_prov`, `state_prov`, `state_name` |
| `district_name` | `X-IPGeo-District-Name` | text | full | `location.district.name`, `district.name`, `location.district`, `district`, `district_name` |
| `city_name` | `X-IPGeo-City-Name` | text | minimal | `location.city.name`, `city.name`, `location.city`, `city`, `city_name` |
| `zip_code` | `X-IPGeo-Zip-Code` | text | standard | `location.zipcode`, `location.zip_code`, `zipcode`, `zip_code`, `postal_code` |
| `latitude` | `X-IPGeo-Latitude` | number | standard | `location.coordinates.latitude`, `location.latitude`, `latitude` |
| `longitude` | `X-IPGeo-Longitude` | number | standard | `location.coordinates.longitude`, `location.longitude`, `longitude` |
| `geoname_id` | `X-IPGeo-Geoname-ID` | text | full | `location.geoname_id`, `geoname_id`, `geo_name_id` |
| `accuracy_radius` | `X-IPGeo-Accuracy-Radius` | number | full | `location.accuracy_radius`, `accuracy_radius` |
| `confidence` | `X-IPGeo-Confidence` | text | full | `location.confidence`, `confidence` |
| `dma_code` | `X-IPGeo-DMA-Code` | text | full | `location.dma_code`, `dma_code` |
| `time_zone` | `X-IPGeo-Time-Zone` | text | standard | `time_zone`, `location.time_zone`, `time_zone.name`, `timezone`, `time_zone_name` |
| `connection_type` | `X-IPGeo-Connection-Type` | text | full | `connection_type`, `location.connection_type` |

## Company, ISP and ASN

| Field | Header | Type | Smallest preset | Database paths |
|---|---|---|---|---|
| `company_name` | `X-IPGeo-Company-Name` | text | full | `company.name`, `network.company.name`, `company_name`, `isp`, `organization` |
| `company_domain` | `X-IPGeo-Company-Domain` | text | full | `company.domain`, `network.company.domain`, `company_domain` |
| `company_type` | `X-IPGeo-Company-Type` | text | full | `company.type`, `network.company.type`, `company_type` |
| `isp_name` | `X-IPGeo-ISP-Name` | text | full | `company.name`, `network.company.name`, `isp`, `company_name` |
| `organization_name` | `X-IPGeo-Organization-Name` | text | standard | `company.name`, `network.company.name`, `asn.organization`, `network.asn.organization`, `organization` |
| `asn` | `X-IPGeo-ASN` | ASN | minimal | `asn.as_number`, `network.asn.as_number`, `asn.asn`, `as_number`, `asn` |
| `asn_number` | `X-IPGeo-ASN-Number` | number | full | `asn.as_number`, `network.asn.as_number`, `as_number`, `asn` |
| `asn_name` | `X-IPGeo-ASN-Name` | text | full | `asn.as_name`, `network.asn.as_name`, `as_name` |
| `asn_organization` | `X-IPGeo-ASN-Organization` | text | full | `asn.organization`, `network.asn.organization`, `as_organization`, `organization` |
| `asn_country` | `X-IPGeo-ASN-Country` | text | full | `asn.country_code`, `asn.country`, `network.asn.country`, `asn_country`, `as_country` |
| `asn_domain` | `X-IPGeo-ASN-Domain` | text | full | `asn.domain`, `network.asn.domain` |
| `asn_type` | `X-IPGeo-ASN-Type` | text | full | `asn.type`, `network.asn.type` |
| `asn_rir` | `X-IPGeo-ASN-RIR` | text | full | `asn.rir`, `asn.whois_host`, `network.asn.rir` |
| `asn_date_allocated` | `X-IPGeo-ASN-Date-Allocated` | text | full | `asn.date_allocated`, `network.asn.date_allocated` |
| `asn_allocation_status` | `X-IPGeo-ASN-Allocation-Status` | text | full | `asn.allocation_status`, `network.asn.allocation_status` |
| `asn_routes` | `X-IPGeo-ASN-Routes` | list | custom only | `asn.routes`, `network.asn.routes` |
| `asn_peers` | `X-IPGeo-ASN-Peers` | list | custom only | `asn.peers`, `network.asn.peers` |
| `asn_upstreams` | `X-IPGeo-ASN-Upstreams` | list | custom only | `asn.upstreams`, `network.asn.upstreams` |
| `asn_downstreams` | `X-IPGeo-ASN-Downstreams` | list | custom only | `asn.downstreams`, `network.asn.downstreams` |

## Security and threat intelligence

| Field | Header | Type | Smallest preset | Database paths |
|---|---|---|---|---|
| `threat_score` | `X-IPGeo-Threat-Score` | number | standard | `threat_score`, `security.threat_score` |
| `is_tor` | `X-IPGeo-Is-Tor` | boolean | standard | `is_tor`, `security.is_tor` |
| `is_proxy` | `X-IPGeo-Is-Proxy` | boolean | standard | `is_proxy`, `security.is_proxy` |
| `is_vpn` | `X-IPGeo-Is-VPN` | boolean | standard | `is_vpn`, `security.is_vpn` |
| `is_relay` | `X-IPGeo-Is-Relay` | boolean | full | `is_relay`, `security.is_relay` |
| `is_residential_proxy` | `X-IPGeo-Is-Residential-Proxy` | boolean | full | `is_residential_proxy`, `security.is_residential_proxy`, presence of `proxy_provider`, presence of `residential_proxy.provider_name`, presence of `residential_proxy_provider_name` |
| `is_anonymous` | `X-IPGeo-Is-Anonymous` | boolean | full | `is_anonymous`, `security.is_anonymous` |
| `is_known_attacker` | `X-IPGeo-Is-Known-Attacker` | boolean | full | `is_known_attacker`, `security.is_known_attacker` |
| `is_bot` | `X-IPGeo-Is-Bot` | boolean | full | `is_bot`, `security.is_bot` |
| `is_spam` | `X-IPGeo-Is-Spam` | boolean | full | `is_spam`, `security.is_spam` |
| `is_cloud_provider` | `X-IPGeo-Is-Cloud-Provider` | boolean | full | `is_cloud_provider`, `security.is_cloud_provider`, presence of `hosting_provider`, presence of `hosting.provider_name` |
| `cloud_provider` | `X-IPGeo-Cloud-Provider` | text | full | `cloud_provider_name`, `security.cloud_provider_name`, `security.cloud_provider`, `cloud_provider` |
| `proxy_type` | `X-IPGeo-Proxy-Type` | text | full | `proxy_type`, `security.proxy_type` |
| `proxy_provider` | `X-IPGeo-Proxy-Provider` | list | full | `proxy_provider_names`, `security.proxy_provider_names`, `security.proxy_provider`, `proxy_provider` |
| `vpn_provider` | `X-IPGeo-VPN-Provider` | list | full | `vpn_provider_names`, `security.vpn_provider_names`, `security.vpn_provider`, `vpn_provider` |
| `relay_provider` | `X-IPGeo-Relay-Provider` | text | full | `relay_provider_name`, `security.relay_provider_name`, `security.relay_provider`, `relay_provider` |
| `proxy_confidence` | `X-IPGeo-Proxy-Confidence` | number | full | `proxy_confidence_score`, `security.proxy_confidence_score` |
| `vpn_confidence` | `X-IPGeo-VPN-Confidence` | number | full | `vpn_confidence_score`, `security.vpn_confidence_score` |
| `proxy_last_seen` | `X-IPGeo-Proxy-Last-Seen` | text | full | `proxy_last_seen`, `security.proxy_last_seen` |
| `vpn_last_seen` | `X-IPGeo-VPN-Last-Seen` | text | full | `vpn_last_seen`, `security.vpn_last_seen` |
| `is_known_good_bot` | `X-IPGeo-Is-Known-Good-Bot` | boolean | full | `is_known_good_bot`, `security.is_known_good_bot` |
| `bot_type` | `X-IPGeo-Bot-Type` | text | full | `bot_type`, `security.bot_type` |
| `bot_operator` | `X-IPGeo-Bot-Operator` | text | full | `bot_operator_name`, `security.bot_operator_name`, `bot_owner_name`, `security.bot_owner_name` |
| `bot_confidence` | `X-IPGeo-Bot-Confidence` | number | full | `bot_confidence_score`, `security.bot_confidence_score` |
| `bot_last_seen` | `X-IPGeo-Bot-Last-Seen` | text | full | `bot_last_seen`, `security.bot_last_seen` |
| `is_corporate_gateway` | `X-IPGeo-Is-Corporate-Gateway` | boolean | full | `is_corporate_gateway`, `security.is_corporate_gateway` |
| `corporate_gateway_provider` | `X-IPGeo-Corporate-Gateway-Provider` | text | full | `corporate_gateway_provider_name`, `security.corporate_gateway_provider_name` |
| `corporate_gateway_type` | `X-IPGeo-Corporate-Gateway-Type` | text | full | `corporate_gateway_type`, `security.corporate_gateway_type` |
| `residential_proxy_provider` | `X-IPGeo-Residential-Proxy-Provider` | text | full | `residential_proxy.provider_name`, `residential_proxy_provider_name`, `proxy_provider`, `security.proxy_provider` |
| `residential_proxy_last_seen` | `X-IPGeo-Residential-Proxy-Last-Seen` | text | full | `residential_proxy.last_seen`, `residential_proxy_last_seen`, `last_seen`, `security.last_seen` |
| `hosting_provider` | `X-IPGeo-Hosting-Provider` | text | full | `hosting_provider`, `security.hosting_provider`, `hosting.provider_name`, `hosting.provider`, `hosting.name` |

## Abuse contact

| Field | Header | Type | Smallest preset | Database paths |
|---|---|---|---|---|
| `abuse_name` | `X-IPGeo-Abuse-Name` | text | full | `abuse.name`, `abuse_name` |
| `abuse_email` | `X-IPGeo-Abuse-Email` | list | full | `abuse.emails`, `abuse.email`, `abuse_email` |
| `abuse_phone` | `X-IPGeo-Abuse-Phone` | list | full | `abuse.phone_numbers`, `abuse.phone`, `abuse_phone` |
| `abuse_address` | `X-IPGeo-Abuse-Address` | text | full | `abuse.address`, `abuse_address` |
| `abuse_country_code` | `X-IPGeo-Abuse-Country-Code` | text | full | `abuse.country_code`, `abuse.country`, `abuse_country` |
| `abuse_kind` | `X-IPGeo-Abuse-Kind` | text | full | `abuse.kind`, `abuse_kind` |
| `abuse_route` | `X-IPGeo-Abuse-Route` | text | full | `abuse.route`, `abuse.network`, `abuse_route` |

## Request metadata

| Field | Header | Type | Smallest preset | Source |
|---|---|---|---|---|
| `ip` | `X-IPGeo-IP` | text | full | the client address Kong determined (`kong.client.get_forwarded_ip()`), IPv4-mapped IPv6 normalised to IPv4 |

## Presets

- **minimal** (3): `country_code`, `city_name`, `asn`
- **standard** (15): `country_code`, `country_name`, `continent_code`, `state_code`, `city_name`, `zip_code`, `latitude`, `longitude`, `time_zone`, `asn`, `organization_name`, `threat_score`, `is_vpn`, `is_proxy`, `is_tor`
- **full** (82): `country_code`, `country_code3`, `country_code_ioc`, `country_name`, `country_name_official`, `country_capital`, `is_eu`, `continent_code`, `continent_name`, `currency_code`, `currency_name`, `currency_symbol`, `calling_code`, `languages`, `tld`, `state_code`, `state_name`, `district_name`, `city_name`, `zip_code`, `latitude`, `longitude`, `geoname_id`, `accuracy_radius`, `confidence`, `dma_code`, `time_zone`, `connection_type`, `company_name`, `company_domain`, `company_type`, `isp_name`, `organization_name`, `asn`, `asn_number`, `asn_name`, `asn_organization`, `asn_country`, `asn_domain`, `asn_type`, `asn_rir`, `asn_date_allocated`, `asn_allocation_status`, `threat_score`, `is_tor`, `is_proxy`, `is_vpn`, `is_relay`, `is_residential_proxy`, `is_anonymous`, `is_known_attacker`, `is_bot`, `is_spam`, `is_cloud_provider`, `cloud_provider`, `proxy_type`, `proxy_provider`, `vpn_provider`, `relay_provider`, `proxy_confidence`, `vpn_confidence`, `proxy_last_seen`, `vpn_last_seen`, `is_known_good_bot`, `bot_type`, `bot_operator`, `bot_confidence`, `bot_last_seen`, `is_corporate_gateway`, `corporate_gateway_provider`, `corporate_gateway_type`, `residential_proxy_provider`, `residential_proxy_last_seen`, `hosting_provider`, `abuse_name`, `abuse_email`, `abuse_phone`, `abuse_address`, `abuse_country_code`, `abuse_kind`, `abuse_route`, `ip`

`full` excludes unbounded lists (`asn_routes`, `asn_peers`, `asn_upstreams`, `asn_downstreams`), which can
hold thousands of entries; map them with `headers.custom` if you need them (values are truncated to
`headers.max_value_length`).
