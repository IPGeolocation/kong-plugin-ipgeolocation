local fields = require "kong.plugins.ipgeolocation.fields"
local headers = require "kong.plugins.ipgeolocation.headers"

describe("headers", function()
  it("derives header names from field names", function()
    assert.equal("X-IPGeo-Country-Code", fields.header_name("country_code"))
    assert.equal("X-IPGeo-City-Name", fields.header_name("city_name"))
    assert.equal("X-IPGeo-ASN", fields.header_name("asn"))
    assert.equal("X-IPGeo-ASN-Organization", fields.header_name("asn_organization"))
    assert.equal("X-IPGeo-Is-VPN", fields.header_name("is_vpn"))
    assert.equal("X-IPGeo-Is-Tor", fields.header_name("is_tor"))
    assert.equal("X-IPGeo-ISP-Name", fields.header_name("isp_name"))
    assert.equal("X-IPGeo-Geoname-ID", fields.header_name("geoname_id"))
    assert.equal("X-IPGeo-Country-Code-IOC", fields.header_name("country_code_ioc"))
    assert.equal("X-IPGeo-IP", fields.header_name("ip"))
    assert.equal("X-IPGeo-Threat-Score", fields.header_name("threat_score"))
  end)

  it("defines the presets shared with the Traefik plugin", function()
    assert.same({ "country_code", "city_name", "asn" }, fields.presets.minimal)
    assert.equal(15, #fields.presets.standard)
    assert.same({}, fields.presets.none)
    local full = {}
    for _, f in ipairs(fields.presets.full) do full[f] = true end
    assert.is_true(full.ip)
    assert.is_true(full.is_known_attacker)
    assert.is_nil(full.asn_routes)        -- unbounded lists are opt-in only
    assert.equal(#fields.list - 4 + 1, #fields.presets.full)
  end)

  it("manages the whole X-IPGeo- namespace in every spelling", function()
    for _, name in ipairs({
      "x-ipgeo-country-code", "X-IPGeo-Country-Code", "X-IPGEO-IS-VPN", "x_ipgeo_country_code",
      "X_IPGeo_Threat_Score", "x-ipgeo_is_tor", "x_ipgeo-anything", "x-ipgeo-dry-run",
    }) do
      assert.is_true(headers.is_managed(name, nil), name)
    end
    for _, name in ipairs({ "x-ipgeolocation", "x-ipgeo", "ipgeo-country", "x-forwarded-for", "x-real-ip" }) do
      assert.is_false(headers.is_managed(name, nil), name)
    end
    local managed = { ["x-country"] = true }
    assert.is_true(headers.is_managed("X-Country", managed))
    assert.is_true(headers.is_managed("x_country", managed))
  end)

  it("removes control characters and truncates on UTF-8 boundaries", function()
    assert.equal("EvilX-Injected: 1", headers.sanitize("Evil\r\nX-Injected: 1"))
    assert.equal("ab", headers.sanitize("a\0b"))
    assert.equal("abc", headers.sanitize("abcdef", 3))
    local s = "aé"                                  -- 'a' + 2-byte é
    assert.equal("a", headers.sanitize(s, 2))      -- never half a character
    assert.equal("aé", headers.sanitize(s, 3))
    local jp = "東京"                               -- 3 bytes per character
    assert.equal("東", headers.sanitize(jp, 5))
    assert.equal("", headers.sanitize(jp, 2))
  end)
end)
