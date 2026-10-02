-- The IPGeolocation.io field catalog.
--
-- Field names, kinds and candidate paths follow the IPGeolocation.io Traefik
-- plugin's catalog (extended with the extra candidates used by the Nginx
-- module), so the same field name means the same data in every
-- IPGeolocation.io edge integration.
--
-- For each field the candidate paths are tried in order: the current nested
-- schema first, older or flatter shapes after it (for example the flat
-- `db-ip-isp.mmdb` layout and bundle databases that nest security data under
-- `security`). A path that ends at a map of translations
-- ({"en": ..., "de": ...}) yields the configured language, falling back to
-- English.
--
-- `presence` paths prove a boolean field true merely by existing: a record in
-- the Residential Proxy database means the address is a residential proxy,
-- and a record in the Hosting database means it belongs to a hosting
-- provider. They are consulted only after every regular path came up empty.

local STRING, BOOL, NUMBER, ASN, LIST = "string", "bool", "number", "asn", "list"

local _M = {
  STRING = STRING, BOOL = BOOL, NUMBER = NUMBER, ASN = ASN, LIST = LIST,
}

local defs = {}
local by_name = {}

local function def(category, name, kind, paths, opts)
  opts = opts or {}
  local f = {
    name = name,
    kind = kind,
    category = category,
    paths = paths,
    presence = opts.presence,
    -- Unbounded fields (routing lists that can run to many kilobytes) are
    -- left out of the "full" preset; map them explicitly if you need them.
    unbounded = opts.unbounded or false,
  }
  defs[#defs + 1] = f
  by_name[name] = f
end

-- Country
def("location", "country_code", STRING, { "location.country.code2", "country.code2", "location.country_code2", "country_code2", "country_code" })
def("location", "country_code3", STRING, { "location.country.code3", "country.code3", "location.country_code3", "country_code3" })
def("location", "country_code_ioc", STRING, { "location.country.code_ioc", "country.code_ioc", "country_code_ioc" })
def("location", "country_name", STRING, { "location.country.name", "country.name", "location.country_name", "country_name" })
def("location", "country_name_official", STRING, { "location.country.name_official", "country.name_official", "location.country_name_official", "country_name_official" })
def("location", "country_capital", STRING, { "location.country.capital", "country.capital", "location.country_capital", "country_capital" })
def("location", "is_eu", BOOL, { "location.is_eu", "is_eu" })

-- Continent
def("location", "continent_code", STRING, { "location.country.continent.code", "country.continent.code", "location.continent_code", "continent_code" })
def("location", "continent_name", STRING, { "location.country.continent.name", "country.continent.name", "location.continent_name", "continent_name" })

-- Country metadata
def("location", "currency_code", STRING, { "location.country.currency.code", "country.currency.code", "currency.code", "currency_code" })
def("location", "currency_name", STRING, { "location.country.currency.name", "country.currency.name", "currency.name", "currency_name" })
def("location", "currency_symbol", STRING, { "location.country.currency.symbol", "country.currency.symbol", "currency.symbol", "currency_symbol" })
def("location", "calling_code", STRING, { "location.country.metadata.calling_code", "country.metadata.calling_code", "country_metadata.calling_code", "calling_code" })
def("location", "languages", LIST, { "location.country.metadata.languages", "country.metadata.languages", "country_metadata.languages", "languages" })
def("location", "tld", STRING, { "location.country.metadata.tld", "country.metadata.tld", "country_metadata.tld", "tld" })

-- Subdivisions and city
def("location", "state_code", STRING, { "location.state.code", "state.code", "location.state_code", "state_code" })
def("location", "state_name", STRING, { "location.state.name", "state.name", "location.state_prov", "state_prov", "state_name" })
def("location", "district_name", STRING, { "location.district.name", "district.name", "location.district", "district", "district_name" })
def("location", "city_name", STRING, { "location.city.name", "city.name", "location.city", "city", "city_name" })

-- Position
def("location", "zip_code", STRING, { "location.zipcode", "location.zip_code", "zipcode", "zip_code", "postal_code" })
def("location", "latitude", NUMBER, { "location.coordinates.latitude", "location.latitude", "latitude" })
def("location", "longitude", NUMBER, { "location.coordinates.longitude", "location.longitude", "longitude" })
def("location", "geoname_id", STRING, { "location.geoname_id", "geoname_id", "geo_name_id" })
def("location", "accuracy_radius", NUMBER, { "location.accuracy_radius", "accuracy_radius" })
def("location", "confidence", STRING, { "location.confidence", "confidence" })
def("location", "dma_code", STRING, { "location.dma_code", "dma_code" })
def("location", "time_zone", STRING, { "time_zone", "location.time_zone", "time_zone.name", "timezone", "time_zone_name" })
def("location", "connection_type", STRING, { "connection_type", "location.connection_type" })

-- Company and ISP
def("network", "company_name", STRING, { "company.name", "network.company.name", "company_name", "isp", "organization" })
def("network", "company_domain", STRING, { "company.domain", "network.company.domain", "company_domain" })
def("network", "company_type", STRING, { "company.type", "network.company.type", "company_type" })
def("network", "isp_name", STRING, { "company.name", "network.company.name", "isp", "company_name" })
def("network", "organization_name", STRING, { "company.name", "network.company.name", "asn.organization", "network.asn.organization", "organization" })

-- ASN
def("network", "asn", ASN, { "asn.as_number", "network.asn.as_number", "asn.asn", "as_number", "asn" })
def("network", "asn_number", NUMBER, { "asn.as_number", "network.asn.as_number", "as_number", "asn" })
def("network", "asn_name", STRING, { "asn.as_name", "network.asn.as_name", "as_name" })
def("network", "asn_organization", STRING, { "asn.organization", "network.asn.organization", "as_organization", "organization" })
def("network", "asn_country", STRING, { "asn.country_code", "asn.country", "network.asn.country", "asn_country", "as_country" })
def("network", "asn_domain", STRING, { "asn.domain", "network.asn.domain" })
def("network", "asn_type", STRING, { "asn.type", "network.asn.type" })
def("network", "asn_rir", STRING, { "asn.rir", "asn.whois_host", "network.asn.rir" })
def("network", "asn_date_allocated", STRING, { "asn.date_allocated", "network.asn.date_allocated" })
def("network", "asn_allocation_status", STRING, { "asn.allocation_status", "network.asn.allocation_status" })
def("network", "asn_routes", LIST, { "asn.routes", "network.asn.routes" }, { unbounded = true })
def("network", "asn_peers", LIST, { "asn.peers", "network.asn.peers" }, { unbounded = true })
def("network", "asn_upstreams", LIST, { "asn.upstreams", "network.asn.upstreams" }, { unbounded = true })
def("network", "asn_downstreams", LIST, { "asn.downstreams", "network.asn.downstreams" }, { unbounded = true })

-- Security and threat intelligence
def("security", "threat_score", NUMBER, { "threat_score", "security.threat_score" })
def("security", "is_tor", BOOL, { "is_tor", "security.is_tor" })
def("security", "is_proxy", BOOL, { "is_proxy", "security.is_proxy" })
def("security", "is_vpn", BOOL, { "is_vpn", "security.is_vpn" })
def("security", "is_relay", BOOL, { "is_relay", "security.is_relay" })
def("security", "is_residential_proxy", BOOL, { "is_residential_proxy", "security.is_residential_proxy" },
    { presence = { "proxy_provider", "residential_proxy.provider_name", "residential_proxy_provider_name" } })
def("security", "is_anonymous", BOOL, { "is_anonymous", "security.is_anonymous" })
def("security", "is_known_attacker", BOOL, { "is_known_attacker", "security.is_known_attacker" })
def("security", "is_bot", BOOL, { "is_bot", "security.is_bot" })
def("security", "is_spam", BOOL, { "is_spam", "security.is_spam" })
def("security", "is_cloud_provider", BOOL, { "is_cloud_provider", "security.is_cloud_provider" },
    { presence = { "hosting_provider", "hosting.provider_name" } })
def("security", "cloud_provider", STRING, { "cloud_provider_name", "security.cloud_provider_name", "security.cloud_provider", "cloud_provider" })
def("security", "proxy_type", STRING, { "proxy_type", "security.proxy_type" })
def("security", "proxy_provider", LIST, { "proxy_provider_names", "security.proxy_provider_names", "security.proxy_provider", "proxy_provider" })
def("security", "vpn_provider", LIST, { "vpn_provider_names", "security.vpn_provider_names", "security.vpn_provider", "vpn_provider" })
def("security", "relay_provider", STRING, { "relay_provider_name", "security.relay_provider_name", "security.relay_provider", "relay_provider" })
def("security", "proxy_confidence", NUMBER, { "proxy_confidence_score", "security.proxy_confidence_score" })
def("security", "vpn_confidence", NUMBER, { "vpn_confidence_score", "security.vpn_confidence_score" })
def("security", "proxy_last_seen", STRING, { "proxy_last_seen", "security.proxy_last_seen" })
def("security", "vpn_last_seen", STRING, { "vpn_last_seen", "security.vpn_last_seen" })

-- Bot detail and corporate gateways. Present in current IPGeolocation.io
-- Security Database releases; resolved when the database has them, empty
-- otherwise. Some releases ship bot_owner_name instead of
-- bot_operator_name, so both are tried.
def("security", "is_known_good_bot", BOOL, { "is_known_good_bot", "security.is_known_good_bot" })
def("security", "bot_type", STRING, { "bot_type", "security.bot_type" })
def("security", "bot_operator", STRING, { "bot_operator_name", "security.bot_operator_name", "bot_owner_name", "security.bot_owner_name" })
def("security", "bot_confidence", NUMBER, { "bot_confidence_score", "security.bot_confidence_score" })
def("security", "bot_last_seen", STRING, { "bot_last_seen", "security.bot_last_seen" })
def("security", "is_corporate_gateway", BOOL, { "is_corporate_gateway", "security.is_corporate_gateway" })
def("security", "corporate_gateway_provider", STRING, { "corporate_gateway_provider_name", "security.corporate_gateway_provider_name" })
def("security", "corporate_gateway_type", STRING, { "corporate_gateway_type", "security.corporate_gateway_type" })

-- Residential proxy and hosting databases
def("security", "residential_proxy_provider", STRING, { "residential_proxy.provider_name", "residential_proxy_provider_name", "proxy_provider", "security.proxy_provider" })
def("security", "residential_proxy_last_seen", STRING, { "residential_proxy.last_seen", "residential_proxy_last_seen", "last_seen", "security.last_seen" })
def("security", "hosting_provider", STRING, { "hosting_provider", "security.hosting_provider", "hosting.provider_name", "hosting.provider", "hosting.name" })

-- Abuse contact
def("abuse", "abuse_name", STRING, { "abuse.name", "abuse_name" })
def("abuse", "abuse_email", LIST, { "abuse.emails", "abuse.email", "abuse_email" })
def("abuse", "abuse_phone", LIST, { "abuse.phone_numbers", "abuse.phone", "abuse_phone" })
def("abuse", "abuse_address", STRING, { "abuse.address", "abuse_address" })
def("abuse", "abuse_country_code", STRING, { "abuse.country_code", "abuse.country", "abuse_country" })
def("abuse", "abuse_kind", STRING, { "abuse.kind", "abuse_kind" })
def("abuse", "abuse_route", STRING, { "abuse.route", "abuse.network", "abuse_route" })

-- The pseudo-field "ip" is the client address the plugin looked up.
_M.IP_FIELD = "ip"

_M.list = defs
_M.by_name = by_name

function _M.is_field(name)
  return name == _M.IP_FIELD or by_name[name] ~= nil
end

-- Header presets, identical to the Traefik plugin's except that "full" omits
-- unbounded fields (see above).
local presets = {
  none = {},
  minimal = { "country_code", "city_name", "asn" },
  standard = {
    "country_code", "country_name", "continent_code", "state_code", "city_name",
    "zip_code", "latitude", "longitude", "time_zone", "asn", "organization_name",
    "threat_score", "is_vpn", "is_proxy", "is_tor",
  },
}
local full = {}
for _, f in ipairs(defs) do
  if not f.unbounded then
    full[#full + 1] = f.name
  end
end
full[#full + 1] = _M.IP_FIELD
presets.full = full
_M.presets = presets

-- Header names: "X-IPGeo-" followed by the field name in Title-Case, with
-- common acronyms upper-cased (country_code -> X-IPGeo-Country-Code,
-- is_vpn -> X-IPGeo-Is-VPN, asn -> X-IPGeo-ASN). HTTP header names are
-- case-insensitive, so these are the same headers the Traefik plugin sets.
_M.HEADER_PREFIX = "X-IPGeo-"

local ACRONYMS = {
  asn = "ASN", ip = "IP", isp = "ISP", vpn = "VPN", tld = "TLD", ioc = "IOC",
  dma = "DMA", eu = "EU", id = "ID", rir = "RIR",
}

function _M.header_name(field)
  local parts = {}
  for part in field:gmatch("[^_]+") do
    parts[#parts + 1] = ACRONYMS[part] or (part:sub(1, 1):upper() .. part:sub(2))
  end
  return _M.HEADER_PREFIX .. table.concat(parts, "-")
end

_M.DRY_RUN_HEADER = "X-IPGeo-Dry-Run"

_M.LANGUAGES = { "en", "de", "ru", "ko", "pt", "ja", "fa", "fr", "zh", "es", "cs", "it" }

return _M
