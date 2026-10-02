local PLUGIN_NAME = "ipgeolocation"

local schema_def = require("kong.plugins." .. PLUGIN_NAME .. ".schema")
local v = require("spec.helpers").validate_plugin_config_schema

describe(PLUGIN_NAME .. ": (schema)", function()
  it("accepts a minimal configuration and fills every default", function()
    local ok, err = v({ databases = { "/data/ipgeolocation/db-ip-location.mmdb" } }, schema_def)
    assert.is_nil(err)
    assert.truthy(ok)
    local c = ok.config
    assert.equal(0, c.database_refresh_interval)
    assert.equal("minimal", c.headers.preset)
    assert.equal("true_false", c.headers.boolean_format)
    assert.equal("en", c.headers.language)
    assert.is_false(c.policy.block_tor)
    assert.is_true(c.policy.fail_open)
    assert.is_true(c.policy.allow_private)
    assert.equal(403, c.policy.status_code)
    -- unset optional fields come back as ngx.null from the schema
    assert.is_true(c.policy.block_threat_score_above == nil or c.policy.block_threat_score_above == ngx.null)
  end)

  it("accepts a complete configuration", function()
    local ok, err = v({
      databases = { "/data/a.mmdb", "/data/b.mmdb" },
      database_refresh_interval = 300,
      headers = { preset = "standard", custom = { ["X-Country"] = "country_code", ["X-IPGeo-Latitude"] = "" },
                  boolean_format = "one_zero", list_separator = "; ", language = "de", max_value_length = 256 },
      policy = { blocked_countries = { "KP" }, blocked_asns = { "AS64500", "64501" }, block_tor = true,
                 block_threat_score_above = 80, exempt_ips = { "10.0.0.0/8", "2001:db8::/32" },
                 dry_run = true, status_code = 451, message = "Unavailable" },
      log_serialize = true,
    }, schema_def)
    assert.is_nil(err)
    assert.truthy(ok)
  end)

  local invalid = {
    { "no database", { databases = {} } },
    { "relative path", { databases = { "data/db.mmdb" } } },
    { "parent segments", { databases = { "/data/../etc/passwd" } } },
    { "directory", { databases = { "/data/" } } },
    { "refresh below 60 seconds", { databases = { "/a.mmdb" }, database_refresh_interval = 30 } },
    { "unknown preset", { databases = { "/a.mmdb" }, headers = { preset = "everything" } } },
    { "unknown field", { databases = { "/a.mmdb" }, headers = { custom = { ["X-A"] = "nope" } } } },
    { "reserved header", { databases = { "/a.mmdb" }, headers = { custom = { Host = "country_code" } } } },
    { "invalid header name", { databases = { "/a.mmdb" }, headers = { custom = { ["X A"] = "country_code" } } } },
    { "allow and block countries", { databases = { "/a.mmdb" }, policy = { allowed_countries = { "US" }, blocked_countries = { "KP" } } } },
    { "three-letter country", { databases = { "/a.mmdb" }, policy = { blocked_countries = { "USA" } } } },
    { "unknown continent", { databases = { "/a.mmdb" }, policy = { blocked_continents = { "XX" } } } },
    { "malformed ASN", { databases = { "/a.mmdb" }, policy = { blocked_asns = { "ASN1" } } } },
    { "threat score above 100", { databases = { "/a.mmdb" }, policy = { block_threat_score_above = 101 } } },
    { "invalid CIDR", { databases = { "/a.mmdb" }, policy = { exempt_ips = { "10.0.0.0/33" } } } },
    { "IPv4-mapped CIDR shorter than /96", { databases = { "/a.mmdb" }, policy = { exempt_ips = { "::ffff:10.0.0.0/8" } } } },
    { "non-error status", { databases = { "/a.mmdb" }, policy = { status_code = 200 } } },
  }
  for _, case in ipairs(invalid) do
    it("rejects " .. case[1], function()
      local ok, err = v(case[2], schema_def)
      assert.is_nil(ok)
      assert.truthy(err)
    end)
  end

  it("cannot be scoped to a consumer (it runs before authentication)", function()
    local ok, err = v({ databases = { "/a.mmdb" } }, schema_def,
                      { consumer = { id = "8a3e4ad1-4d06-4e9b-9e7c-6b2a2a0a8b62" } })
    assert.is_nil(ok)
    assert.truthy(err.consumer)
  end)
end)
