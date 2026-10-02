-- Security policy: compiled once per plugin configuration, evaluated per
-- request against resolved field values.
--
-- Rules run in this order and the first one that blocks wins (the same order
-- as the IPGeolocation.io Traefik plugin):
--   1. allowed_countries / blocked_countries
--   2. allowed_continents / blocked_continents
--   3. allowed_asns / blocked_asns
--   4. security flags (Tor, VPN, proxy, ...)
--   5. block_threat_score_above
--
-- "Unknown" is deliberately narrow. An allow list cannot be decided when the
-- value is unknown, so `allow_unknown` decides. Block lists, security flags
-- and the threat score only block on positive evidence: the Security Database
-- covers flagged ranges, so an address without a security record is
-- not flagged, not "unknown".

local resolver = require "kong.plugins.ipgeolocation.resolver"

local type, ipairs, upper, tostring = type, ipairs, string.upper, tostring
local normalize_asn = resolver.normalize_asn

local _M = {}

-- flag, field, reason, field that spares the request when true
local SECURITY_RULES = {
  { "block_tor", "is_tor", "address is flagged as a Tor exit node" },
  { "block_vpn", "is_vpn", "address is flagged as a VPN" },
  { "block_proxy", "is_proxy", "address is flagged as a proxy" },
  { "block_relay", "is_relay", "address is flagged as a relay" },
  { "block_residential_proxy", "is_residential_proxy", "address is flagged as a residential proxy" },
  { "block_anonymous", "is_anonymous", "address is flagged as anonymous" },
  { "block_known_attacker", "is_known_attacker", "address is flagged as a known attacker" },
  { "block_bot", "is_bot", "address is flagged as a bot", "is_known_good_bot" },
  { "block_spam", "is_spam", "address is flagged as a spam source" },
  { "block_cloud_provider", "is_cloud_provider", "address belongs to a cloud or hosting provider" },
  { "block_corporate_gateway", "is_corporate_gateway", "address is flagged as a corporate gateway" },
}
_M.SECURITY_RULES = SECURITY_RULES

local function upper_set(list)
  if type(list) ~= "table" or #list == 0 then
    return nil
  end
  local set, any = {}, false
  for _, v in ipairs(list) do
    if type(v) == "string" then
      set[upper(v)] = true
      any = true
    end
  end
  return any and set or nil
end

local function asn_set(list)
  if type(list) ~= "table" or #list == 0 then
    return nil
  end
  local set, any = {}, false
  for _, v in ipairs(list) do
    local a = (type(v) == "string" or type(v) == "number") and normalize_asn(tostring(v)) or nil
    if a then
      set[a] = true
      any = true
    end
  end
  return any and set or nil
end

function _M.compile(p)
  p = p or {}
  local c = {
    allowed_countries = upper_set(p.allowed_countries),
    blocked_countries = upper_set(p.blocked_countries),
    allowed_continents = upper_set(p.allowed_continents),
    blocked_continents = upper_set(p.blocked_continents),
    allowed_asns = asn_set(p.allowed_asns),
    blocked_asns = asn_set(p.blocked_asns),
    threat_above = type(p.block_threat_score_above) == "number" and p.block_threat_score_above or nil,
    allow_unknown = p.allow_unknown ~= false,
    rules = {},
    required = {},
  }

  local required, seen = c.required, {}
  local function need(field)
    if not seen[field] then
      seen[field] = true
      required[#required + 1] = field
    end
  end

  if c.allowed_countries or c.blocked_countries then need("country_code") end
  if c.allowed_continents or c.blocked_continents then need("continent_code") end
  if c.allowed_asns or c.blocked_asns then need("asn") end
  if c.threat_above ~= nil then need("threat_score") end

  for _, r in ipairs(SECURITY_RULES) do
    if p[r[1]] == true then
      local unless = r[4]
      if unless and p.block_known_good_bots == true then
        unless = nil
      end
      c.rules[#c.rules + 1] = { field = r[2], reason = r[3], unless = unless }
      need(r[2])
      if unless then need(unless) end
    end
  end

  c.active = #required > 0
  return c
end

-- Returns nil when the request is allowed, otherwise the reason it is not.
-- Reasons are for logs and dry-run headers; they are never sent to clients.
--
-- `degraded` is set when a database failed and the configuration fails
-- open. A value may then be unknown only because of the failure, so allow
-- lists let unknown values pass whatever `allow_unknown` says; positive
-- evidence from the databases that did answer still blocks.
function _M.evaluate(c, values, degraded)
  if not c.active then
    return nil
  end
  local allow_unknown = c.allow_unknown or degraded == true

  if c.allowed_countries or c.blocked_countries then
    local country = values.country_code
    country = type(country) == "string" and upper(country) or nil
    if c.allowed_countries then
      if not country then
        if not allow_unknown then
          return "country is unknown"
        end
      elseif not c.allowed_countries[country] then
        return "country " .. country .. " is not in allowed_countries"
      end
    end
    if c.blocked_countries and country and c.blocked_countries[country] then
      return "country " .. country .. " is in blocked_countries"
    end
  end

  if c.allowed_continents or c.blocked_continents then
    local continent = values.continent_code
    continent = type(continent) == "string" and upper(continent) or nil
    if c.allowed_continents then
      if not continent then
        if not allow_unknown then
          return "continent is unknown"
        end
      elseif not c.allowed_continents[continent] then
        return "continent " .. continent .. " is not in allowed_continents"
      end
    end
    if c.blocked_continents and continent and c.blocked_continents[continent] then
      return "continent " .. continent .. " is in blocked_continents"
    end
  end

  if c.allowed_asns or c.blocked_asns then
    local asn = values.asn
    asn = type(asn) == "string" and asn or nil
    if c.allowed_asns then
      if not asn then
        if not allow_unknown then
          return "ASN is unknown"
        end
      elseif not c.allowed_asns[asn] then
        return asn .. " is not in allowed_asns"
      end
    end
    if c.blocked_asns and asn and c.blocked_asns[asn] then
      return asn .. " is in blocked_asns"
    end
  end

  local rules = c.rules
  for i = 1, #rules do
    local r = rules[i]
    if values[r.field] == true and not (r.unless and values[r.unless] == true) then
      return r.reason
    end
  end

  if c.threat_above ~= nil then
    local score = values.threat_score
    if type(score) == "number" and score > c.threat_above then
      return "threat score " .. resolver.num2str(score) .. " is above " .. c.threat_above
    end
  end

  return nil
end

return _M
