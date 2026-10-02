local policy = require "kong.plugins.ipgeolocation.policy"

describe("policy", function()
  local function eval(p, values)
    return policy.evaluate(policy.compile(p), values)
  end

  it("is inactive without rules", function()
    local c = policy.compile({})
    assert.is_false(c.active)
    assert.is_nil(policy.evaluate(c, { is_tor = true }))
  end)

  it("lists only the fields its rules need", function()
    local c = policy.compile({ blocked_countries = { "kp" }, block_bot = true, block_threat_score_above = 80 })
    table.sort(c.required)
    assert.same({ "country_code", "is_bot", "is_known_good_bot", "threat_score" }, c.required)
  end)

  it("applies country allow and block lists", function()
    assert.is_nil(eval({ allowed_countries = { "US", "ca" } }, { country_code = "CA" }))
    assert.equal("country DE is not in allowed_countries", eval({ allowed_countries = { "US" } }, { country_code = "DE" }))
    assert.equal("country KP is in blocked_countries", eval({ blocked_countries = { "KP" } }, { country_code = "kp" }))
    assert.is_nil(eval({ blocked_countries = { "KP" } }, { country_code = "DE" }))
  end)

  it("lets allow_unknown decide only for allow lists", function()
    assert.is_nil(eval({ allowed_countries = { "US" } }, {}))
    assert.equal("country is unknown", eval({ allowed_countries = { "US" }, allow_unknown = false }, {}))
    assert.is_nil(eval({ blocked_countries = { "KP" }, allow_unknown = false }, {}))
    assert.equal("continent is unknown", eval({ allowed_continents = { "EU" }, allow_unknown = false }, {}))
    assert.equal("ASN is unknown", eval({ allowed_asns = { "AS1" }, allow_unknown = false }, {}))
    -- security rules never treat a missing record as a reason to block
    assert.is_nil(eval({ block_tor = true, allow_unknown = false }, {}))
  end)

  it("lets unknown values pass allow lists while degraded, but still blocks on evidence", function()
    local c = policy.compile({ allowed_countries = { "US" }, allowed_continents = { "NA" },
                               allowed_asns = { "AS1" }, allow_unknown = false })
    assert.is_nil(policy.evaluate(c, {}, true))
    assert.equal("country DE is not in allowed_countries", policy.evaluate(c, { country_code = "DE" }, true))
    assert.is_string(policy.evaluate(policy.compile({ block_tor = true }), { is_tor = true }, true))
    assert.equal("country is unknown", policy.evaluate(c, {}, false))
  end)

  it("applies continent and ASN lists, accepting AS-prefixed and bare numbers", function()
    assert.equal("continent AS is in blocked_continents", eval({ blocked_continents = { "AS" } }, { continent_code = "AS" }))
    assert.is_nil(eval({ allowed_continents = { "EU" } }, { continent_code = "EU" }))
    assert.equal("AS64500 is in blocked_asns", eval({ blocked_asns = { "64500" } }, { asn = "AS64500" }))
    assert.equal("AS64500 is in blocked_asns", eval({ blocked_asns = { "as64500" } }, { asn = "AS64500" }))
    assert.equal("AS64501 is not in allowed_asns", eval({ allowed_asns = { "AS64500" } }, { asn = "AS64501" }))
  end)

  it("blocks on each security flag only when it is set", function()
    local cases = {
      { "block_tor", "is_tor" }, { "block_vpn", "is_vpn" }, { "block_proxy", "is_proxy" },
      { "block_relay", "is_relay" }, { "block_residential_proxy", "is_residential_proxy" },
      { "block_anonymous", "is_anonymous" }, { "block_known_attacker", "is_known_attacker" },
      { "block_bot", "is_bot" }, { "block_spam", "is_spam" }, { "block_cloud_provider", "is_cloud_provider" },
      { "block_corporate_gateway", "is_corporate_gateway" },
    }
    for _, c in ipairs(cases) do
      assert.is_string(eval({ [c[1]] = true }, { [c[2]] = true }), c[1])
      assert.is_nil(eval({ [c[1]] = true }, { [c[2]] = false }), c[1])
      assert.is_nil(eval({ [c[1]] = false }, { [c[2]] = true }), c[1])
      assert.is_nil(eval({ [c[1]] = true }, {}), c[1])
    end
  end)

  it("spares known good bots unless block_known_good_bots is set", function()
    assert.is_nil(eval({ block_bot = true }, { is_bot = true, is_known_good_bot = true }))
    assert.is_string(eval({ block_bot = true }, { is_bot = true, is_known_good_bot = false }))
    assert.is_string(eval({ block_bot = true, block_known_good_bots = true }, { is_bot = true, is_known_good_bot = true }))
  end)

  it("blocks when the threat score is strictly above the threshold", function()
    assert.is_nil(eval({ block_threat_score_above = 80 }, { threat_score = 80 }))
    assert.equal("threat score 81 is above 80", eval({ block_threat_score_above = 80 }, { threat_score = 81 }))
    assert.is_string(eval({ block_threat_score_above = 0 }, { threat_score = 1 }))
    assert.is_nil(eval({ block_threat_score_above = 80 }, {}))
    assert.is_nil(eval({ block_threat_score_above = 80 }, { threat_score = "high" }))
  end)

  it("evaluates rules in a fixed order", function()
    local reason = eval({ blocked_countries = { "PK" }, block_tor = true, block_threat_score_above = 10 },
                        { country_code = "PK", is_tor = true, threat_score = 99 })
    assert.equal("country PK is in blocked_countries", reason)
  end)
end)
