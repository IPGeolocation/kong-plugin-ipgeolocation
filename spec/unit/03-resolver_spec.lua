local resolver = require "kong.plugins.ipgeolocation.resolver"
local plan_mod = require "kong.plugins.ipgeolocation.plan"
local registry = require "kong.plugins.ipgeolocation.registry"
local iputil = require "kong.plugins.ipgeolocation.iputil"
local W = require "spec.ipgeolocation.mmdb_writer"
local helpers = require "spec.ipgeolocation.helpers"
local kong_mock = require "spec.ipgeolocation.kong_mock"

describe("resolver", function()
  local fx, dir

  lazy_setup(function()
    fx = helpers.fixtures()
    dir = helpers.tmpdir()
  end)

  before_each(function()
    kong_mock.install()
  end)

  after_each(function()
    registry.reset()
    kong_mock.uninstall()
  end)

  local function resolve(dbs, ip, headers_conf)
    local custom = {}
    for _, f in ipairs(headers_conf and headers_conf.fields or {}) do
      custom["X-T-" .. f] = f
    end
    local conf = helpers.conf({
      databases = dbs,
      headers = { preset = headers_conf and headers_conf.preset or "full", custom = custom,
                  list_separator = headers_conf and headers_conf.sep or ",",
                  language = headers_conf and headers_conf.language or "en" },
    })
    local plan = assert(plan_mod.compile(conf))
    local b, n = assert(iputil.parse(ip))
    return resolver.resolve(plan, b, n, registry.get)
  end

  it("resolves location fields from the nested schema", function()
    local v, t, found, failure = resolve({ fx.location }, "203.0.113.50")
    assert.is_true(found)
    assert.is_nil(failure)
    assert.equal("PK", v.country_code)
    assert.equal("PAK", v.country_code3)
    assert.equal("Pakistan", v.country_name)
    assert.equal("Islamic Republic of Pakistan", v.country_name_official)
    assert.equal("Islamabad", v.country_capital)
    assert.equal("AS", v.continent_code)
    assert.equal("Asia", v.continent_name)
    assert.equal("PKR", v.currency_code)
    assert.equal("Pakistani Rupee", v.currency_name)
    assert.equal("+92", v.calling_code)
    assert.equal("ur-PK,en-PK,pa,sd,ps,brh", t.languages)
    assert.equal("PK-PB", v.state_code)
    assert.equal("Punjab", v.state_name)
    assert.equal("Lahore District", v.district_name)
    assert.equal("Lahore", v.city_name)
    assert.equal("54000", v.zip_code)
    assert.equal(31.54972, v.latitude)
    assert.equal("31.54972", t.latitude)        -- database text is preserved for headers
    assert.equal("1172451", v.geoname_id)
    assert.equal("Asia/Karachi", v.time_zone)
    assert.equal(5.5, v.accuracy_radius)
    assert.equal("high", v.confidence)
    assert.equal("Fiber", v.connection_type)
    assert.is_nil(v.dma_code)                     -- "" means no data
  end)

  it("resolves IPv6 addresses", function()
    local v = resolve({ fx.location, fx.asn }, "2001:db8:1::abcd")
    assert.equal("JP", v.country_code)
    assert.equal("Tokyo", v.city_name)
    assert.equal("AS64503", v.asn)
  end)

  it("normalises booleans, including string booleans: \"false\" must be false", function()
    local v = resolve({ fx.security }, "203.0.113.11")
    assert.is_true(v.is_vpn)
    assert.is_false(v.is_tor)          -- stored as the string "false"
    assert.is_false(v.is_known_attacker)
    assert.equal(60, v.threat_score)
    v = resolve({ fx.security }, "203.0.113.21")
    assert.is_true(v.is_tor)           -- stored as an MMDB boolean
    assert.equal(91, v.threat_score)   -- stored as uint16
    v = resolve({ fx.security }, "203.0.113.22")
    assert.is_true(v.is_vpn)           -- stored as "TRUE"
    assert.equal(88, v.threat_score)   -- stored as the string "88"
  end)

  it("joins provider lists with the configured separator", function()
    local v, t = resolve({ fx.security }, "203.0.113.11")
    assert.same({ "Nord VPN", "Proton VPN" }, v.vpn_provider)
    assert.equal("Nord VPN,Proton VPN", t.vpn_provider)
    assert.is_nil(v.proxy_provider)    -- empty array means no data
    local _, t2 = resolve({ fx.security }, "203.0.113.12", { sep = "; " })
    assert.equal("Oxy Labs; Geonode", t2.proxy_provider)
    assert.equal(99, (resolve({ fx.security }, "203.0.113.12")).proxy_confidence)
  end)

  it("resolves the Security Database bot and corporate gateway fields", function()
    local v = resolve({ fx.security }, "203.0.113.14")
    assert.is_true(v.is_bot)
    assert.is_true(v.is_known_good_bot)
    assert.equal("search_engine", v.bot_type)
    assert.equal("Example Search", v.bot_operator)
    assert.equal(99, v.bot_confidence)
    v = resolve({ fx.security }, "203.0.113.18")
    assert.is_true(v.is_corporate_gateway)
    assert.equal("SWG", v.corporate_gateway_type)
    assert.equal("Example Gateway", v.corporate_gateway_provider)
  end)

  it("layers databases: each field comes from the first database that has it", function()
    local a = resolve({ fx.location, fx.asn, fx.security }, "203.0.113.10")
    local b = resolve({ fx.security, fx.asn, fx.location }, "203.0.113.10")
    for _, f in ipairs({ "country_code", "city_name", "asn", "asn_organization", "is_tor", "threat_score" }) do
      assert.equal(a[f], b[f], f)
    end
    assert.equal("PK", a.country_code)
    assert.equal("AS64500", a.asn)
    assert.is_true(a.is_tor)
  end)

  it("does not let an empty value shadow a later database", function()
    local p = dir .. "/empty-city.mmdb"
    local w = W.new()
    w:insert("203.0.113.0/24", { location = { city = { name = { en = "" } }, country = { code2 = "XX" } } })
    w:write(p)
    local v = resolve({ p, fx.location }, "203.0.113.50")
    assert.equal("Lahore", v.city_name)   -- "" in the first database is "no data"
    assert.equal("XX", v.country_code)    -- a real value in the first database wins
  end)

  it("reads the flat db-ip-isp.mmdb layout", function()
    local v = resolve({ fx.isp }, "203.0.113.9")
    assert.equal("PK", v.country_code)
    assert.equal("Pakistan", v.country_name)
    assert.equal("AS64500", v.asn)
    assert.equal(64500, v.asn_number)
    assert.equal("Example Telecom ISP", v.isp_name)
    assert.equal("Example Telecom ISP", v.company_name)
    assert.equal("Example Telecom PK", v.asn_organization)
    assert.equal("PK", v.asn_country)
    assert.equal("Fiber", v.connection_type)
  end)

  it("reads bundles that nest security data under 'security'", function()
    local v = resolve({ fx.bundle }, "198.51.100.10")
    assert.equal("DE", v.country_code)
    assert.is_true(v.is_vpn)
    assert.equal(65, v.threat_score)
    assert.equal("Example VPN", v.vpn_provider[1])
    assert.equal("AS64501", v.asn)
    v = resolve({ fx.bundle }, "198.51.100.11")
    assert.is_false(v.is_vpn)
    assert.equal("Example GmbH", v.company_name)
    assert.equal("Example GmbH", v.organization_name)
  end)

  it("derives flags from the Residential Proxy and Hosting databases by presence", function()
    local v = resolve({ fx.residential, fx.hosting }, "203.0.113.30")
    assert.is_true(v.is_residential_proxy)
    assert.equal("Example Residential Proxies", v.residential_proxy_provider)
    assert.equal("2026-09-08", v.residential_proxy_last_seen)
    v = resolve({ fx.residential, fx.hosting }, "203.0.113.31")
    assert.is_true(v.is_cloud_provider)
    assert.equal("Example Hosting Inc.", v.hosting_provider)
    -- an explicit flag in an earlier database wins over presence
    v = resolve({ fx.security, fx.residential }, "203.0.113.30")
    assert.is_true(v.is_residential_proxy)
  end)

  it("resolves company, ASN and abuse contact fields", function()
    local v, t = resolve({ fx.company, fx.asn, fx.abuse }, "203.0.113.9")
    assert.equal("Example Telecom Ltd.", v.company_name)
    assert.equal("example.pk", v.company_domain)
    assert.equal("ISP", v.company_type)
    assert.equal("Example Telecom Ltd.", v.organization_name)
    assert.equal("Example Telecom PK", v.asn_organization)
    assert.equal("ISP", v.asn_type)
    assert.equal("Example NOC", v.abuse_name)
    assert.equal("abuse@example.pk", t.abuse_email)
    assert.equal("203.0.113.0/24", v.abuse_route)
  end)

  it("selects the configured language and falls back to English", function()
    local v = resolve({ fx.location }, "198.51.100.7", { language = "de" })
    assert.equal("Deutschland", v.country_name)
    assert.equal("Berlin", v.city_name)          -- no German city name: English
    v = resolve({ fx.location }, "203.0.113.7", { language = "ja" })
    assert.equal("パキスタン", v.country_name)
  end)

  it("reports unavailable and broken databases without losing the others", function()
    local v, _, found, failure = resolve({ dir .. "/missing.mmdb", fx.location }, "203.0.113.5")
    assert.is_true(found)
    assert.equal("PK", v.country_code)
    assert.matches("missing.mmdb", failure)
  end)

  it("treats an IPv6 client and an IPv4-only database as 'no data', not a failure", function()
    local p = dir .. "/v4only.mmdb"
    local w = W.new({ ip_version = 4 })
    w:insert("203.0.113.0/24", { location = { country = { code2 = "PK" } } })
    w:write(p)
    local v, _, found, failure = resolve({ p, fx.location }, "2001:db8:1::1")
    assert.is_true(found)
    assert.is_nil(failure)
    assert.equal("JP", v.country_code)
  end)

  it("returns nothing for addresses no database covers", function()
    local v, _, found, failure = resolve({ fx.location, fx.security }, "203.0.114.1")
    assert.is_false(found)
    assert.is_nil(failure)
    assert.same({}, v)
  end)

  it("formats values the way the Traefik plugin does", function()
    local fmt = resolver.format_value
    assert.equal("AS15169", (fmt("15169", "asn")))
    assert.equal("AS15169", (fmt("as15169", "asn")))
    assert.equal("AS15169", (fmt(15169, "asn")))
    assert.is_nil(fmt("0", "asn"))
    assert.is_nil(fmt("AS0", "asn"))
    assert.equal(1257, (fmt("AS1257", "number")))
    assert.equal("37.38605", select(2, fmt("37.38605", "number")))
    assert.equal("-122.08385", select(2, fmt(-122.08385, "number")))
    assert.equal("80", select(2, fmt(80, "number")))
    assert.is_false(fmt("false", "bool"))
    assert.is_false(fmt("no", "bool"))
    assert.is_true(fmt("1", "bool"))
    assert.is_nil(fmt("", "bool"))
    assert.is_nil(fmt("   ", "string"))
    assert.equal("x", (fmt("  x ", "string")))
  end)
end)
