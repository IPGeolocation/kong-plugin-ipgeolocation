-- Deterministic fixture databases shaped like the real IPGeolocation.io
-- releases (field names, nesting, and value encodings were taken from the
-- official sample databases: string booleans, numbers stored as strings,
-- integer scores, provider lists, 12-language name maps, the flat ISP
-- layout, bundles nesting security data under "security").
--
-- Only documentation address space is used (RFC 5737, RFC 3849) and
-- documentation AS numbers (RFC 5398).

local W = require "spec.ipgeolocation.mmdb_writer"

local _M = {}

local LANGS = { "cs", "de", "en", "es", "fa", "fr", "it", "ja", "ko", "pt", "ru", "zh" }

local function names(en, overrides)
  local t = {}
  for _, l in ipairs(LANGS) do t[l] = "" end
  t.en = en
  for k, v in pairs(overrides or {}) do t[k] = v end
  return t
end

local function country(code2, code3, name, continent_code, continent_name, capital, currency, extra)
  return {
    capital = names(capital),
    code2 = code2,
    code3 = code3,
    code_ioc = code3,
    continent = { code = continent_code, name = names(continent_name) },
    currency = { code = currency[1], name = { en = currency[2] }, symbol = currency[3] },
    metadata = { calling_code = extra.calling_code, languages = extra.languages, tld = extra.tld },
    name = names(name, extra.names),
    name_official = names(extra.official or name),
  }
end

local PK = country("PK", "PAK", "Pakistan", "AS", "Asia", "Islamabad", { "PKR", "Pakistani Rupee", "₨" },
                   { calling_code = "+92", languages = "ur-PK,en-PK,pa,sd,ps,brh", tld = ".pk",
                     names = { de = "Pakistan", ja = "パキスタン" }, official = "Islamic Republic of Pakistan" })
local DE = country("DE", "DEU", "Germany", "EU", "Europe", "Berlin", { "EUR", "Euro", "€" },
                   { calling_code = "+49", languages = "de", tld = ".de",
                     names = { de = "Deutschland", ja = "ドイツ連邦共和国" }, official = "Federal Republic of Germany" })
local US = country("US", "USA", "United States", "NA", "North America", "Washington, D.C.", { "USD", "US Dollar", "$" },
                   { calling_code = "+1", languages = "en-US,es-US,haw,fr", tld = ".us",
                     names = { de = "USA" }, official = "United States of America" })
local JP = country("JP", "JPN", "Japan", "AS", "Asia", "Tokyo", { "JPY", "Yen", "¥" },
                   { calling_code = "+81", languages = "ja", tld = ".jp", names = { ja = "日本" } })

local function location(c, state_code, state, district, city, zip, lat, lon, geoname, tz, advance)
  local rec = {
    location = {
      city = { name = names(city) },
      coordinates = { latitude = lat, longitude = lon },
      country = c,
      district = { name = names(district) },
      geoname_id = geoname,
      state = { code = state_code, name = names(state) },
      zipcode = zip,
    },
    time_zone = tz,
  }
  if advance then
    rec.location.accuracy_radius = advance.accuracy_radius
    rec.location.confidence = advance.confidence
    rec.location.dma_code = advance.dma_code or ""
    rec.connection_type = advance.connection_type
  end
  return rec
end

_M.locations = {
  ["203.0.113.0/24"] = location(PK, "PK-PB", "Punjab", "Lahore District", "Lahore", "54000", "31.54972", "74.34361",
                                "1172451", "Asia/Karachi", { accuracy_radius = "5.5", confidence = "high", connection_type = "Fiber" }),
  ["198.51.100.0/24"] = location(DE, "DE-BE", "Berlin", "Berlin", "Berlin", "10115", "52.52437", "13.41053",
                                 "2950159", "Europe/Berlin", { accuracy_radius = "3.2", confidence = "high", connection_type = "Cable" }),
  ["192.0.2.0/24"] = location(US, "US-CA", "California", "Santa Clara County", "Mountain View", "94043", "37.38605",
                              "-122.08385", "5375480", "America/Los_Angeles", { accuracy_radius = "8", confidence = "medium", dma_code = "807", connection_type = "DSL" }),
  -- A more specific network inside 192.0.2.0/24.
  ["192.0.2.128/25"] = location(US, "US-CA", "California", "San Francisco County", "San Francisco", "94103", "37.77493",
                                "-122.41942", "5391959", "America/Los_Angeles", { accuracy_radius = "4", confidence = "high", connection_type = "Fiber" }),
  ["2001:db8:1::/48"] = location(JP, "JP-13", "Tokyo", "Chiyoda", "Tokyo", "100-0001", "35.6895", "139.69171",
                                 "1850147", "Asia/Tokyo", { accuracy_radius = "2", confidence = "high", connection_type = "Fiber" }),
  ["2001:db8:2::/48"] = location(DE, "DE-HE", "Hesse", "Frankfurt", "Frankfurt am Main", "60311", "50.11552", "8.68417",
                                 "2925533", "Europe/Berlin", { accuracy_radius = "6", confidence = "low", connection_type = "Mobile" }),
}

local function security(t)
  local rec = {
    bot_confidence_score = 0, bot_last_seen = "", bot_operator_name = "", bot_type = "",
    cloud_provider_name = "", corporate_gateway_provider_name = "", corporate_gateway_type = "",
    is_anonymous = "false", is_bot = "false", is_cloud_provider = "false", is_corporate_gateway = "false",
    is_known_attacker = "false", is_known_good_bot = "false", is_proxy = "false", is_relay = "false",
    is_residential_proxy = "false", is_spam = "false", is_tor = "false", is_vpn = "false",
    proxy_confidence_score = 0, proxy_last_seen = "", proxy_provider_names = W.array({}),
    relay_provider_name = "", threat_score = 0, vpn_confidence_score = 0, vpn_last_seen = "",
    vpn_provider_names = W.array({}),
  }
  for k, v in pairs(t) do rec[k] = v end
  return rec
end

_M.security = {
  ["203.0.113.10/32"] = security({ is_tor = "true", is_anonymous = "true", threat_score = 90 }),
  ["203.0.113.11/32"] = security({ is_vpn = "true", is_anonymous = "true", threat_score = 60,
                                   vpn_provider_names = W.array({ "Nord VPN", "Proton VPN" }),
                                   vpn_confidence_score = 99, vpn_last_seen = "2026-09-20" }),
  ["203.0.113.12/32"] = security({ is_proxy = "true", is_residential_proxy = "true", is_anonymous = "true",
                                   threat_score = 45, proxy_provider_names = W.array({ "Oxy Labs", "Geonode" }),
                                   proxy_confidence_score = 99, proxy_last_seen = "2026-09-11" }),
  ["203.0.113.13/32"] = security({ is_known_attacker = "true", threat_score = 95 }),
  ["203.0.113.14/32"] = security({ is_bot = "true", is_known_good_bot = "true", bot_type = "search_engine",
                                   bot_operator_name = "Example Search", bot_confidence_score = 99, threat_score = 5 }),
  ["203.0.113.15/32"] = security({ is_bot = "true", bot_type = "scraper", bot_operator_name = "Example Scraper",
                                   bot_confidence_score = 80, threat_score = 70 }),
  ["203.0.113.16/32"] = security({ is_spam = "true", threat_score = 50 }),
  ["203.0.113.17/32"] = security({ is_cloud_provider = "true", cloud_provider_name = "Example Cloud", threat_score = 20 }),
  ["203.0.113.18/32"] = security({ is_corporate_gateway = "true", corporate_gateway_type = "SWG",
                                   corporate_gateway_provider_name = "Example Gateway" }),
  ["203.0.113.19/32"] = security({ is_relay = "true", is_anonymous = "true", relay_provider_name = "iCloud Private Relay",
                                   threat_score = 10 }),
  ["203.0.113.20/32"] = security({ threat_score = 85 }),
  -- Encoding variants seen across releases: real MMDB booleans, string scores.
  ["203.0.113.21/32"] = security({ is_tor = true, is_anonymous = true, threat_score = W.uint16(91) }),
  ["203.0.113.22/32"] = security({ threat_score = "88", is_vpn = "TRUE" }),
  ["2001:db8:1::10/128"] = security({ is_tor = "true", is_anonymous = "true", threat_score = 90 }),
}

local function asn(number, org, cc, domain, typ)
  return { asn = { as_number = number, country_code = cc, domain = domain, organization = org, type = typ } }
end

_M.asn = {
  ["203.0.113.0/24"] = asn("64500", "Example Telecom PK", "PK", "example.pk", "ISP"),
  ["198.51.100.0/24"] = asn("64501", "Example Carrier DE", "DE", "example.de", "ISP"),
  ["192.0.2.0/24"] = asn("64502", "Example Hosting US", "US", "example.com", "HOSTING"),
  ["2001:db8::/32"] = asn("64503", "Example IPv6 Net", "JP", "example.jp", "ISP"),
}

_M.company = {
  ["203.0.113.0/24"] = { company = { domain = "example.pk", name = { en = "Example Telecom Ltd." }, type = "ISP" } },
  ["198.51.100.0/24"] = { company = { domain = "example.de", name = { en = "Example GmbH" }, type = "BUSINESS" } },
}

-- The flat db-ip-isp.mmdb layout (no "location" wrapper).
_M.isp = {
  ["203.0.113.0/24"] = { as_country = "PK", as_organization = "Example Telecom PK", asn = "64500",
                         connection_type = "Fiber", country = PK, isp = "Example Telecom ISP" },
}

-- A bundle: location, ASN, company and security in one file, security nested.
_M.bundle = {
  ["198.51.100.0/24"] = {
    asn = { as_number = "64501", country_code = "DE", domain = "example.de", organization = "Example Carrier DE", type = "ISP" },
    company = { domain = "example.de", name = { en = "Example GmbH" }, type = "BUSINESS" },
    location = _M.locations["198.51.100.0/24"].location,
    security = security({ threat_score = 0 }),
    time_zone = "Europe/Berlin",
  },
  ["198.51.100.10/32"] = {
    asn = { as_number = "64501", country_code = "DE", domain = "example.de", organization = "Example Carrier DE", type = "ISP" },
    location = _M.locations["198.51.100.0/24"].location,
    security = security({ is_vpn = "true", is_anonymous = "true", threat_score = 65,
                          vpn_provider_names = W.array({ "Example VPN" }) }),
    time_zone = "Europe/Berlin",
  },
}

_M.residential = {
  ["203.0.113.30/32"] = { last_seen = "2026-09-08", proxy_provider = "Example Residential Proxies" },
}

_M.hosting = {
  ["203.0.113.31/32"] = { hosting_provider = "Example Hosting Inc." },
}

_M.abuse = {
  ["203.0.113.0/24"] = { abuse = { address = "1 Example Road, Lahore", country_code = "PK",
                                   emails = "abuse@example.pk", kind = "group", name = { en = "Example NOC" },
                                   phone_numbers = "+92 42 0000000", route = "203.0.113.0/24" } },
}

local SPECS = {
  location = { data = "locations", record_size = 28, alias_ipv4_mapped = true,
               languages = { "en", "de", "ru", "ko", "pt", "ja", "fa", "fr", "zh-CN", "es", "cs", "it" },
               database_type = "ipgeolocation.io Database" },
  security = { data = "security", record_size = 32, database_type = "ipgeolocation.io IP-Security Database" },
  asn = { data = "asn", record_size = 24, database_type = "ipgeolocation.io Database" },
  company = { data = "company", record_size = 32 },
  isp = { data = "isp", record_size = 32 },
  bundle = { data = "bundle", record_size = 32 },
  residential = { data = "residential", record_size = 32, database_type = "ipgeolocation.io Residential Database" },
  hosting = { data = "hosting", record_size = 24, database_type = "ipgeolocation.io IP Hosting Database" },
  abuse = { data = "abuse", record_size = 32 },
}
_M.SPECS = SPECS

function _M.build(name, path, opts)
  local spec = assert(SPECS[name], "unknown fixture " .. tostring(name))
  opts = opts or {}
  local w = W.new({
    record_size = opts.record_size or spec.record_size,
    alias_ipv4_mapped = spec.alias_ipv4_mapped,
    languages = spec.languages,
    database_type = spec.database_type,
    data_padding = opts.data_padding,
  })
  local nets = {}
  for cidr in pairs(_M[spec.data]) do nets[#nets + 1] = cidr end
  table.sort(nets)
  for _, cidr in ipairs(nets) do
    w:insert(cidr, _M[spec.data][cidr])
  end
  return w:write(path)
end

-- Builds every fixture into `dir` and returns name -> path.
function _M.build_all(dir)
  os.execute("mkdir -p '" .. dir .. "'")
  local out = {}
  for name in pairs(SPECS) do
    out[name] = _M.build(name, dir .. "/" .. name .. ".mmdb")
  end
  return out
end

return _M
