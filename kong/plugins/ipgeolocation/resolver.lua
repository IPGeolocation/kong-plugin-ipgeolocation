-- Turns per-database extraction results into IPGeolocation.io field values.
--
-- Semantics (shared with the Nginx module and the Traefik plugin):
--   * databases are consulted in configured order; for every field the first
--     database that yields a non-empty value wins, which is how a Location
--     database and a Security Database layer without configuration;
--   * within a database, candidate paths are tried in catalog order;
--   * empty strings mean "no data" (IPGeolocation.io stores "" rather than
--     null) and never shadow a later database;
--   * booleans stored as strings ("true"/"false"), as real MMDB booleans or as
--     numbers are all normalised to Lua booleans.
--
-- Each resolved field has a typed value (exported to other plugins through
-- kong.ctx.shared) and a display string (used for request headers). Display
-- strings keep the database's own text for numbers stored as strings, so
-- header values match what the Nginx and Traefik integrations emit.

local fields = require "kong.plugins.ipgeolocation.fields"
local mmdb = require "kong.plugins.ipgeolocation.mmdb"

local type, tonumber, tostring = type, tonumber, tostring
local floor, abs = math.floor, math.abs
local byte, sub, lower, upper, match, format = string.byte, string.sub, string.lower, string.upper,
                                                string.match, string.format
local concat = table.concat

local BOOL, NUMBER, ASN = fields.BOOL, fields.NUMBER, fields.ASN
local ERR_IPV6_IN_IPV4 = mmdb.ERR_IPV6_IN_IPV4

local _M = {}

local function trim(s)
  local first, last = byte(s, 1), byte(s, -1)
  if first and (first <= 32 or last <= 32) then
    return match(s, "^%s*(.-)%s*$")
  end
  return s
end
_M.trim = trim

-- Integers print without a fraction; other numbers use the shortest fixed
-- notation that round-trips (no exponent), as the Traefik plugin does.
local function num2str(n)
  if n ~= n or n == math.huge or n == -math.huge then
    return nil
  end
  if n == floor(n) and abs(n) < 2^53 then
    return format("%d", n)
  end
  for digits = 1, 17 do
    local s = format("%." .. digits .. "f", n)
    if tonumber(s) == n then
      return s
    end
  end
  return format("%.17f", n)
end
_M.num2str = num2str

local function bool_from_string(s)
  s = lower(trim(s))
  if s == "" then
    return nil
  end
  return s == "true" or s == "1" or s == "yes" or s == "on"
end

function _M.normalize_asn(s)
  s = upper(trim(s))
  if sub(s, 1, 2) == "AS" then
    s = trim(sub(s, 3))
  end
  if s == "" or s == "0" then
    return nil
  end
  return "AS" .. s
end

-- Formats a raw decoded value for a field kind. Returns typed value and
-- display string (display may be nil for booleans), or nil when empty.
local function format_value(raw, kind, sep)
  local t = type(raw)

  if kind == BOOL then
    if t == "boolean" then
      return raw
    elseif t == "string" then
      return bool_from_string(raw)
    elseif t == "number" then
      return raw ~= 0
    end
    return nil
  end

  if kind == ASN then
    local s
    if t == "number" then
      s = num2str(raw)
    elseif t == "string" then
      s = raw
    else
      return nil
    end
    if not s then
      return nil
    end
    s = _M.normalize_asn(s)
    return s, s
  end

  if kind == NUMBER then
    if t == "number" then
      local s = num2str(raw)
      if not s then
        return nil
      end
      return raw, s
    elseif t == "string" then
      local s = trim(raw)
      if upper(sub(s, 1, 2)) == "AS" then
        s = trim(sub(s, 3))
      end
      if s == "" then
        return nil
      end
      local n = tonumber(s)
      if n ~= nil then
        return n, s
      end
      return s, s
    elseif t == "boolean" then
      return raw, raw and "true" or "false"
    end
    return nil
  end

  -- STRING and LIST
  if t == "string" then
    local s = trim(raw)
    if s == "" then
      return nil
    end
    return s, s
  elseif t == "number" then
    local s = num2str(raw)
    if not s then
      return nil
    end
    return s, s
  elseif t == "boolean" then
    local s = raw and "true" or "false"
    return s, s
  elseif t == "table" then
    local items, n = {}, 0
    for i = 1, #raw do
      local v = raw[i]
      local tv, s = type(v), nil
      if tv == "string" then
        s = trim(v)
      elseif tv == "number" then
        s = num2str(v)
      elseif tv == "boolean" then
        s = v and "true" or "false"
      end
      if s and s ~= "" then
        n = n + 1
        items[n] = s
      end
    end
    if n == 0 then
      return nil
    end
    return items, concat(items, sep)
  end
  return nil
end
_M.format_value = format_value

local function non_empty(raw)
  local t = type(raw)
  if t == "string" then
    return trim(raw) ~= ""
  elseif t == "table" then
    return #raw > 0
  elseif t == "boolean" then
    return raw
  end
  return raw ~= nil
end

-- Looks the address up in every configured database and resolves the plan's
-- fields.
--
-- `get_reader(path)` returns a reader or nil plus an error.
-- Returns: values (field -> typed), texts (field -> display string),
--          found (any database had a record), failure (first error or nil).
function _M.resolve(plan, ip, n, get_reader)
  local dbs = plan.databases
  local ndb = #dbs
  local outs = {}
  local found = false
  local failure

  for i = 1, ndb do
    local path = dbs[i]
    local reader, err = get_reader(path)
    if not reader then
      failure = failure or (path .. ": " .. (err or "database unavailable"))
    else
      local off, info = reader:lookup(ip, n)
      if off then
        local out = {}
        local ok, xerr = reader:extract(off, plan.trie, out, plan.lang)
        if ok then
          outs[i] = out
          found = true
        else
          failure = failure or (path .. ": " .. xerr)
        end
      elseif off == nil and info ~= ERR_IPV6_IN_IPV4 then
        -- An IPv6 client and an IPv4-only database simply mean "no data";
        -- anything else is a broken database.
        failure = failure or (path .. ": " .. tostring(info))
      end
    end
  end

  local values, texts = {}, {}
  if not found then
    return values, texts, false, failure
  end

  local sep = plan.list_separator
  local plan_fields = plan.fields
  for fi = 1, #plan_fields do
    local f = plan_fields[fi]
    local slots, presence, kind = f.slots, f.presence_slots, f.kind
    for i = 1, ndb do
      local out = outs[i]
      if out then
        local v, s
        for si = 1, #slots do
          local raw = out[slots[si]]
          if raw ~= nil then
            v, s = format_value(raw, kind, sep)
            if v ~= nil then
              break
            end
          end
        end
        if v == nil and presence then
          for si = 1, #presence do
            local raw = out[presence[si]]
            if raw ~= nil and non_empty(raw) then
              v = true
              break
            end
          end
        end
        if v ~= nil then
          values[f.name] = v
          texts[f.name] = s
          break
        end
      end
    end
  end

  return values, texts, true, failure
end

return _M
