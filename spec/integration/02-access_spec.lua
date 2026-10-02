local helpers = require "spec.helpers"
local fixtures = require "spec.ipgeolocation.fixtures"

local PLUGIN_NAME = "ipgeolocation"
local DB_DIR = os.getenv("IPGEO_FIXTURE_DIR") or "/tmp/kong-plugin-ipgeolocation-fixtures"

for _, strategy in helpers.all_strategies() do
  if strategy ~= "cassandra" then
    describe(PLUGIN_NAME .. ": (access) [#" .. strategy .. "]", function()
      local client
      local db

      lazy_setup(function()
        db = fixtures.build_all(DB_DIR)
        os.execute("chmod -R a+rX '" .. DB_DIR .. "'")
        local bp = helpers.get_db_utils(strategy == "off" and "postgres" or strategy, nil, { PLUGIN_NAME })

        local function route(host, config, extra)
          local r = bp.routes:insert(extra or { hosts = { host } })
          if config then
            bp.plugins:insert({ name = PLUGIN_NAME, route = { id = r.id }, config = config })
          end
          return r
        end

        local all = { db.location, db.asn, db.security }
        route("enrich.test", { databases = all, headers = { preset = "standard" } })
        route("block.test", { databases = all, policy = { block_tor = true, block_known_attacker = true,
                                                          block_threat_score_above = 80 } })
        route("dryrun.test", { databases = all, policy = { block_vpn = true, dry_run = true } })
        route("closed.test", { databases = { "/nonexistent/db-ip-security.mmdb" }, policy = { fail_open = false } })
        route("open.test", { databases = { "/nonexistent/db-ip-security.mmdb", db.location },
                             policy = { block_tor = true } })

        -- Service-scoped instance.
        local svc = bp.services:insert({
          name = "service-scoped",
          host = helpers.mock_upstream_host,
          port = helpers.mock_upstream_port,
          protocol = helpers.mock_upstream_protocol,
        })
        bp.routes:insert({ hosts = { "service.test" }, service = { id = svc.id } })
        bp.plugins:insert({ name = PLUGIN_NAME, service = { id = svc.id },
                            config = { databases = { db.location }, headers = { preset = "none",
                                       custom = { ["X-Service-Country"] = "country_code" } } } })

        -- Global instance, overridden by the route and service instances above.
        bp.plugins:insert({ name = PLUGIN_NAME, config = { databases = { db.location, db.asn } } })
        route("global.test")

        assert(helpers.start_kong({
          database = strategy,
          nginx_conf = "spec/fixtures/custom_nginx.template",
          plugins = "bundled," .. PLUGIN_NAME,
          declarative_config = strategy == "off" and helpers.make_yaml_file() or nil,
          trusted_ips = "127.0.0.1,::1",
          real_ip_header = "X-Forwarded-For",
          real_ip_recursive = "on",
        }))
      end)

      lazy_teardown(function()
        helpers.stop_kong(nil, true)
      end)

      before_each(function()
        client = helpers.proxy_client()
      end)

      after_each(function()
        if client then client:close() end
      end)

      local function get(host, ip, headers)
        local h = { host = host, ["X-Forwarded-For"] = ip }
        for k, val in pairs(headers or {}) do h[k] = val end
        return client:get("/request", { headers = h })
      end

      it("enriches the upstream request (route instance)", function()
        local r = get("enrich.test", "203.0.113.5")
        assert.response(r).has.status(200)
        assert.equal("PK", assert.request(r).has.header("x-ipgeo-country-code"))
        assert.equal("Lahore", assert.request(r).has.header("x-ipgeo-city-name"))
        assert.equal("AS64500", assert.request(r).has.header("x-ipgeo-asn"))
        assert.equal("Asia/Karachi", assert.request(r).has.header("x-ipgeo-time-zone"))
      end)

      it("replaces client-supplied X-IPGeo headers", function()
        local r = get("enrich.test", "203.0.113.5", {
          ["X-IPGeo-Country-Code"] = "US",
          ["X_IPGeo_Is_VPN"] = "false",
          ["x-ipgeo-is-known-attacker"] = "false",
        })
        assert.response(r).has.status(200)
        assert.equal("PK", assert.request(r).has.header("x-ipgeo-country-code"))
        assert.request(r).has.no.header("x_ipgeo_is_vpn")
        assert.request(r).has.no.header("x-ipgeo-is-known-attacker")
      end)

      it("uses Kong's real-IP result, not the left-most X-Forwarded-For entry", function()
        local r = get("enrich.test", "198.51.100.7, 203.0.113.5")
        assert.response(r).has.status(200)
        assert.equal("PK", assert.request(r).has.header("x-ipgeo-country-code"))
      end)

      it("enriches IPv6 clients", function()
        local r = get("enrich.test", "2001:db8:1::abcd")
        assert.response(r).has.status(200)
        assert.equal("JP", assert.request(r).has.header("x-ipgeo-country-code"))
      end)

      it("blocks flagged addresses without disclosing the reason", function()
        local r = get("block.test", "203.0.113.10")
        local body = assert.response(r).has.status(403)
        assert.matches("Access denied", body, nil, true)
        assert.not_matches("Tor", body, nil, true)
        assert.response(get("block.test", "203.0.113.13")).has.status(403)
        assert.response(get("block.test", "203.0.113.20")).has.status(403)   -- threat score 85
      end)

      it("does not block clean addresses or addresses without a security record", function()
        assert.response(get("block.test", "203.0.113.11")).has.status(200)  -- VPN, score 60
        assert.response(get("block.test", "203.0.113.200")).has.status(200) -- no record
      end)

      it("reports instead of blocking in dry-run mode", function()
        local r = get("dryrun.test", "203.0.113.11")
        assert.response(r).has.status(200)
        assert.equal("address is flagged as a VPN", assert.request(r).has.header("x-ipgeo-dry-run"))
      end)

      it("honours fail_open", function()
        assert.response(get("closed.test", "203.0.113.5")).has.status(403)
        local r = get("open.test", "203.0.113.5")
        assert.response(r).has.status(200)
        assert.equal("PK", assert.request(r).has.header("x-ipgeo-country-code"))
      end)

      it("applies a service-scoped instance", function()
        local r = get("service.test", "198.51.100.7")
        assert.response(r).has.status(200)
        assert.equal("DE", assert.request(r).has.header("x-service-country"))
        assert.request(r).has.no.header("x-ipgeo-country-code")   -- the global instance is overridden
      end)

      it("applies the global instance where nothing more specific is configured", function()
        local r = get("global.test", "198.51.100.7")
        assert.response(r).has.status(200)
        assert.equal("DE", assert.request(r).has.header("x-ipgeo-country-code"))
        assert.equal("AS64501", assert.request(r).has.header("x-ipgeo-asn"))
      end)

      it("skips private addresses", function()
        local r = client:get("/request", { headers = { host = "enrich.test" } })
        assert.response(r).has.status(200)
        assert.request(r).has.no.header("x-ipgeo-country-code")
      end)
    end)
  end
end
