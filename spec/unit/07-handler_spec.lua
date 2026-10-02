local helpers = require "spec.ipgeolocation.helpers"
local kong_mock = require "spec.ipgeolocation.kong_mock"
local registry = require "kong.plugins.ipgeolocation.registry"
local resolver = require "kong.plugins.ipgeolocation.resolver"
local W = require "spec.ipgeolocation.mmdb_writer"

local handler

describe("handler", function()
  local fx, req

  lazy_setup(function()
    fx = helpers.fixtures()
    handler = require "kong.plugins.ipgeolocation.handler"
  end)

  after_each(function()
    registry.reset()
    kong_mock.uninstall()
  end)

  -- Runs one request through the plugin: rewrite (global instance) and/or access.
  local function run(conf, opts)
    opts = opts or {}
    req = kong_mock.install({ ip = opts.ip, headers = opts.headers })
    handler:configure({ conf })
    if opts.rewrite_conf then
      handler:rewrite(opts.rewrite_conf)
    end
    handler:access(conf)
    return req
  end

  local function conf(over)
    return helpers.conf(helpers.deep_merge({ databases = { fx.location, fx.asn, fx.security } }, over or {}))
  end

  it("enriches the request with the minimal preset", function()
    local r = run(conf(), { ip = "203.0.113.5" })
    assert.equal("PK", r.upstream["x-ipgeo-country-code"])
    assert.equal("Lahore", r.upstream["x-ipgeo-city-name"])
    assert.equal("AS64500", r.upstream["x-ipgeo-asn"])
    assert.is_nil(r.upstream["x-ipgeo-is-tor"])
    assert.is_nil(r.exit)
  end)

  it("replaces client-supplied X-IPGeo headers with the real answer", function()
    local r = run(conf({ headers = { preset = "standard" } }), {
      ip = "203.0.113.5",
      headers = {
        ["X-IPGeo-Country-Code"] = "US",
        ["x-ipgeo-is-vpn"] = "false",
        ["X_IPGeo_Threat_Score"] = "0",
        ["x-ipgeo-is-known-attacker"] = "false",   -- not set by this configuration
        ["X-IPGeo-Dry-Run"] = "spoofed",
        ["X-Unrelated"] = "kept",
      },
    })
    assert.equal("PK", r.upstream["x-ipgeo-country-code"])
    -- no Security record for this address: the spoofed value is removed and
    -- the header stays absent ("no data"), exactly as Nginx and Traefik do
    assert.is_nil(r.upstream["x-ipgeo-is-vpn"])
    assert.is_nil(r.upstream["x_ipgeo_threat_score"])
    assert.is_nil(r.upstream["x-ipgeo-is-known-attacker"])
    assert.is_nil(r.upstream["x-ipgeo-dry-run"])
    assert.equal("kept", r.upstream["x-unrelated"])
  end)

  it("sets security headers from the Security Database, overriding spoofed values", function()
    local r = run(conf({ headers = { preset = "standard" } }), {
      ip = "203.0.113.11", headers = { ["X-IPGeo-Is-VPN"] = "false", ["X-IPGeo-Threat-Score"] = "0" } })
    assert.equal("true", r.upstream["x-ipgeo-is-vpn"])
    assert.equal("false", r.upstream["x-ipgeo-is-tor"])
    assert.equal("60", r.upstream["x-ipgeo-threat-score"])
  end)

  it("strips spoofed headers even for private addresses and exempt addresses", function()
    local r = run(conf(), { ip = "10.0.0.7", headers = { ["X-IPGeo-Country-Code"] = "US" } })
    assert.is_nil(r.upstream["x-ipgeo-country-code"])
    assert.is_true(kong.ctx.shared.ipgeolocation.private)
    r = run(conf({ policy = { exempt_ips = { "203.0.113.0/24" }, block_tor = true } }),
            { ip = "203.0.113.10", headers = { ["X-IPGeo-Country-Code"] = "US" } })
    assert.equal("PK", r.upstream["x-ipgeo-country-code"])
    assert.is_nil(r.exit)
    assert.is_true(kong.ctx.shared.ipgeolocation.exempt)
  end)

  it("never reads X-Forwarded-For or X-Real-IP itself", function()
    local r = run(conf(), { ip = "127.0.0.1", headers = {
      ["X-Forwarded-For"] = "203.0.113.10", ["X-Real-IP"] = "203.0.113.10" } })
    assert.is_nil(r.upstream["x-ipgeo-country-code"])   -- loopback per Kong: no lookup
    assert.equal("127.0.0.1", kong.ctx.shared.ipgeolocation.ip)
  end)

  it("treats IPv4-mapped IPv6 client addresses as IPv4", function()
    local r = run(conf({ policy = { block_tor = true } }), { ip = "::ffff:203.0.113.10" })
    assert.equal(403, r.exit.status)
    assert.equal("203.0.113.10", kong.ctx.shared.ipgeolocation.ip)
  end)

  it("blocks with a generic message and records the reason internally", function()
    local r = run(conf({ policy = { block_tor = true } }), { ip = "203.0.113.10" })
    assert.same({ status = 403, message = "Access denied" }, r.exit)
    local result = kong.ctx.shared.ipgeolocation
    assert.is_true(result.blocked)
    assert.equal("address is flagged as a Tor exit node", result.reason)
    assert.equal(1, #kong_mock.logged(r, "info", "blocked 203.0.113.10"))
  end)

  it("uses the configured status code and message", function()
    local r = run(conf({ policy = { blocked_countries = { "PK" }, status_code = 451, message = "Unavailable here" } }),
                  { ip = "203.0.113.5" })
    assert.same({ status = 451, message = "Unavailable here" }, r.exit)
  end)

  it("does not block clean addresses that have no security record", function()
    local r = run(conf({ policy = { block_tor = true, block_vpn = true, block_known_attacker = true,
                                    block_threat_score_above = 10, allow_unknown = false } }),
                  { ip = "203.0.113.200" })
    assert.is_nil(r.exit)
    assert.equal("PK", r.upstream["x-ipgeo-country-code"])
  end)

  it("does not mistake the string \"false\" for true", function()
    local r = run(conf({ policy = { block_tor = true, block_proxy = true, block_spam = true } }),
                  { ip = "203.0.113.11" })                      -- a VPN, nothing else
    assert.is_nil(r.exit)
  end)

  it("blocks IPv6 clients", function()
    local r = run(conf({ policy = { block_tor = true } }), { ip = "2001:db8:1::10" })
    assert.equal(403, r.exit.status)
  end)

  it("applies the threat score threshold strictly", function()
    assert.is_nil(run(conf({ policy = { block_threat_score_above = 85 } }), { ip = "203.0.113.20" }).exit)
    assert.equal(403, run(conf({ policy = { block_threat_score_above = 84 } }), { ip = "203.0.113.20" }).exit.status)
  end)

  it("spares known good bots", function()
    assert.is_nil(run(conf({ policy = { block_bot = true } }), { ip = "203.0.113.14" }).exit)
    assert.equal(403, run(conf({ policy = { block_bot = true } }), { ip = "203.0.113.15" }).exit.status)
  end)

  it("reports instead of blocking in dry-run mode", function()
    local r = run(conf({ policy = { block_known_attacker = true, dry_run = true } }), { ip = "203.0.113.13" })
    assert.is_nil(r.exit)
    assert.equal("address is flagged as a known attacker", r.upstream["x-ipgeo-dry-run"])
    assert.is_true(kong.ctx.shared.ipgeolocation.dry_run)
    assert.is_false(kong.ctx.shared.ipgeolocation.blocked)
  end)

  it("fails open by default when a database is unavailable", function()
    local c = conf({ databases = { "/nonexistent/db.mmdb", fx.location }, policy = { block_tor = true } })
    local r = run(c, { ip = "203.0.113.5" })
    assert.is_nil(r.exit)
    assert.equal("PK", r.upstream["x-ipgeo-country-code"])
    assert.equal(1, #kong_mock.logged(r, "warn", "IP intelligence unavailable"))
  end)

  it("fails closed when fail_open is false", function()
    local c = conf({ databases = { "/nonexistent/db.mmdb", fx.location }, policy = { fail_open = false } })
    local r = run(c, { ip = "203.0.113.5" })
    assert.equal(403, r.exit.status)
    assert.equal("IP intelligence unavailable", kong.ctx.shared.ipgeolocation.reason)
  end)

  it("handles a client address that is not an IP address", function()
    local r = run(conf({ policy = { block_tor = true } }), { ip = "unix:" })
    assert.is_nil(r.exit)
    r = run(conf({ policy = { fail_open = false } }), { ip = "unix:" })
    assert.equal(403, r.exit.status)
  end)

  it("lets allow_unknown decide for allow lists", function()
    local c = conf({ policy = { allowed_countries = { "US" }, allow_unknown = false } })
    assert.equal(403, run(c, { ip = "203.0.114.1" }).exit.status)    -- not in any database
    assert.equal(403, run(c, { ip = "203.0.113.1" }).exit.status)    -- PK
    assert.is_nil(run(c, { ip = "192.0.2.10" }).exit)                -- US
  end)

  it("does not let allow lists block unknown values while failing open", function()
    local c = conf({ databases = { "/nonexistent/db.mmdb", fx.location },
                     policy = { allowed_countries = { "US" }, allow_unknown = false } })
    assert.is_nil(run(c, { ip = "203.0.114.1" }).exit)                -- not in any database
    assert.equal(403, run(c, { ip = "203.0.113.1" }).exit.status)    -- PK: positive evidence still blocks
    assert.is_nil(run(c, { ip = "192.0.2.10" }).exit)                -- US
    c = conf({ databases = { "/nonexistent/db.mmdb", fx.location },
               policy = { allowed_countries = { "US" }, allow_unknown = false, fail_open = false } })
    assert.equal(403, run(c, { ip = "203.0.114.1" }).exit.status)
    assert.equal("IP intelligence unavailable", kong.ctx.shared.ipgeolocation.reason)
  end)

  it("maps custom header names and strips client-supplied copies of them", function()
    local r = run(conf({ headers = { preset = "none", custom = { ["X-Country"] = "country_code", ["X-Client-IP"] = "ip" } } }),
                  { ip = "203.0.113.5", headers = { ["X-Country"] = "US", ["x_country"] = "US" } })
    assert.equal("PK", r.upstream["x-country"])
    assert.is_nil(r.upstream["x_country"])
    assert.equal("203.0.113.5", r.upstream["x-client-ip"])
    assert.is_nil(r.upstream["x-ipgeo-country-code"])
  end)

  it("formats booleans as configured", function()
    local c = conf({ headers = { preset = "none", custom = { ["X-IPGeo-Is-VPN"] = "is_vpn" }, boolean_format = "one_zero" } })
    assert.equal("1", run(c, { ip = "203.0.113.11" }).upstream["x-ipgeo-is-vpn"])
    assert.equal("0", run(c, { ip = "203.0.113.10" }).upstream["x-ipgeo-is-vpn"])
  end)

  it("never forwards control characters from a database", function()
    local dir = helpers.tmpdir()
    local w = W.new()
    w:insert("203.0.113.0/24", { location = { city = { name = { en = "Evil\r\nX-Injected: yes" } }, country = { code2 = "PK" } } })
    local path = w:write(dir .. "/evil.mmdb")
    local r = run(conf({ databases = { path } }), { ip = "203.0.113.5" })
    assert.equal("EvilX-Injected: yes", r.upstream["x-ipgeo-city-name"])
    assert.is_nil(r.upstream["x-injected"])
  end)

  it("exports the result to other plugins and optionally to the log serializer", function()
    local r = run(conf({ log_serialize = true, policy = { block_vpn = true, dry_run = true } }), { ip = "203.0.113.11" })
    local result = kong.ctx.shared.ipgeolocation
    assert.equal("203.0.113.11", result.ip)
    assert.is_true(result.found)
    assert.equal("PK", result.fields.country_code)
    assert.is_true(result.fields.is_vpn)
    assert.equal(r.serialized.ipgeolocation.reason, "address is flagged as a VPN")
    assert.equal("PK", r.serialized.ipgeolocation.fields.country_code)
  end)

  it("re-uses the rewrite result when the same (global) instance runs in access", function()
    local c = conf({ __plugin_id = "global-1" })
    local calls = 0
    local real = resolver.resolve
    resolver.resolve = function(...) calls = calls + 1 return real(...) end
    local r = run(c, { ip = "203.0.113.5", rewrite_conf = c })
    resolver.resolve = real
    assert.equal(1, calls)
    assert.equal("PK", r.upstream["x-ipgeo-country-code"])
  end)

  it("lets a more specific instance override the global one from rewrite", function()
    local global = conf({ __plugin_id = "global-1",
                          headers = { preset = "standard", custom = { ["X-Country"] = "country_code" } } })
    local route = conf({ __plugin_id = "route-1", headers = { preset = "minimal" }, policy = { block_tor = true } })
    local r = run(route, { ip = "203.0.113.10", rewrite_conf = global })
    assert.is_nil(r.upstream["x-country"])            -- set by the global instance, removed
    assert.is_nil(r.upstream["x-ipgeo-threat-score"]) -- standard-only header, removed
    assert.equal("PK", r.upstream["x-ipgeo-country-code"])
    assert.equal(403, r.exit.status)                  -- the route instance's policy applies
  end)

  it("treats null (ngx.null-style userdata) options as unset", function()
    local null = newproxy(false)
    local c = conf({ policy = { block_vpn = true } })
    c.policy.block_threat_score_above = null
    c.policy.status_code = null
    c.policy.message = null
    c.headers.language = null
    c.headers.list_separator = null
    c.headers.max_value_length = null
    c.database_refresh_interval = null
    local r = run(c, { ip = "203.0.113.11" })                  -- VPN with threat score 60
    assert.same({ status = 403, message = "Access denied" }, r.exit)
    assert.equal("PK", r.upstream["x-ipgeo-country-code"])
    r = run(c, { ip = "203.0.113.20" })                        -- score 85, threshold null
    assert.is_nil(r.exit)
  end)

  it("enumerates every request header when stripping", function()
    local r = run(conf(), { ip = "203.0.113.5" })
    assert.is_true(r.get_headers_calls >= 1)          -- the mock asserts max_headers == 0
  end)
end)
