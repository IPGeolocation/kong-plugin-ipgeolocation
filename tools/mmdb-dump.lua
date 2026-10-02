-- Dumps records for a list of IP addresses as canonical JSON lines, using the
-- plugin's own MMDB reader. Used by crosscheck.py to compare against an
-- independent implementation (libmaxminddb / python-maxminddb).
--
-- usage: resty tools/mmdb-dump.lua <database.mmdb> <ip-list-file>
local mmdb = require "kong.plugins.ipgeolocation.mmdb"
local iputil = require "kong.plugins.ipgeolocation.iputil"

-- Every byte >= 0x80 is escaped as \u00XX so that binary ("bytes") values and
-- UTF-8 strings survive the round trip; crosscheck.py compares both sides in
-- this "one code point per byte" form.
local function esc(s)
  return (s:gsub('[%c"\\\128-\255]', function(c)
    if c == '"' then return '\\"' elseif c == "\\" then return "\\\\" end
    return string.format("\\u%04x", c:byte())
  end))
end

local function enc(v)
  local t = type(v)
  if t == "string" then return '"' .. esc(v) .. '"' end
  if t == "number" then
    if v ~= v then return "NaN" end
    if v == math.huge then return "Infinity" end
    if v == -math.huge then return "-Infinity" end
    if v == math.floor(v) and math.abs(v) < 2^53 then return string.format("%d", v) end
    return string.format("%.17g", v)
  end
  if t == "boolean" then return tostring(v) end
  if t == "nil" then return "null" end
  if getmetatable(v) == mmdb.array_mt then
    local parts = {}
    for i = 1, #v do parts[i] = enc(v[i]) end
    return "[" .. table.concat(parts, ",") .. "]"
  end
  local keys = {}
  for k in pairs(v) do keys[#keys + 1] = k end
  table.sort(keys)
  local parts = {}
  for i, k in ipairs(keys) do parts[i] = '"' .. esc(k) .. '":' .. enc(v[k]) end
  return "{" .. table.concat(parts, ",") .. "}"
end

local path, list = arg[1], arg[2]
local db = assert(mmdb.open(path))
for ip in io.lines(list) do
  local b, n = iputil.parse(ip)
  local out
  if not b then
    out = '{"ip":"' .. esc(ip) .. '","error":"parse"}'
  else
    local off, plen = db:lookup(b, n)
    if off == nil then
      out = '{"ip":"' .. esc(ip) .. '","error":' .. enc(plen) .. '}'
    elseif off == false then
      out = '{"ip":"' .. esc(ip) .. '","prefix":' .. plen .. ',"record":null}'
    else
      local rec, err = db:record(off)
      if not rec then
        out = '{"ip":"' .. esc(ip) .. '","error":' .. enc(err) .. '}'
      else
        out = '{"ip":"' .. esc(ip) .. '","prefix":' .. plen .. ',"record":' .. enc(rec) .. '}'
      end
    end
  end
  io.write(out, "\n")
end
db:close()
