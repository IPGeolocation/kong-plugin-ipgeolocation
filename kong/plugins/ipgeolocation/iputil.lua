-- IP address utilities: strict parsing into byte arrays, IPv4-mapped IPv6
-- normalisation, private/loopback classification and CIDR matching.
--
-- Addresses are represented as Lua arrays of byte values (1-based) with a
-- length of 4 (IPv4) or 16 (IPv6).

local tonumber, type, ipairs = tonumber, type, ipairs
local find, sub, lower, match, gmatch = string.find, string.sub, string.lower, string.match, string.gmatch
local concat = table.concat
local floor = math.floor

local _M = {}

local function parse_ipv4(s)
  local a, b, c, d = match(s, "^(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)$")
  if not a then
    return nil
  end
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if a > 255 or b > 255 or c > 255 or d > 255 then
    return nil
  end
  return { a, b, c, d }
end

local function parse_groups(part, groups, allow_v4)
  if part == "" then
    return true
  end
  local fields = {}
  for f in gmatch(part .. ":", "([^:]*):") do
    fields[#fields + 1] = f
  end
  local last = #fields
  for i, f in ipairs(fields) do
    if allow_v4 and i == last and find(f, ".", 1, true) then
      local v4 = parse_ipv4(f)
      if not v4 then
        return nil
      end
      groups[#groups + 1] = v4[1] * 256 + v4[2]
      groups[#groups + 1] = v4[3] * 256 + v4[4]
    else
      local n = #f
      if n < 1 or n > 4 or find(f, "[^%x]") then
        return nil
      end
      groups[#groups + 1] = tonumber(f, 16)
    end
  end
  return true
end

local function parse_ipv6(s)
  local zone = find(s, "%", 1, true)
  if zone then
    s = sub(s, 1, zone - 1)
  end
  if #s < 2 or #s > 45 then
    return nil
  end
  local groups
  local dbl = find(s, "::", 1, true)
  if dbl then
    if find(s, "::", dbl + 1, true) then
      return nil
    end
    local head, tail = {}, {}
    if not parse_groups(sub(s, 1, dbl - 1), head, false)
       or not parse_groups(sub(s, dbl + 2), tail, true)
    then
      return nil
    end
    local missing = 8 - #head - #tail
    if missing < 1 then
      return nil
    end
    groups = head
    for _ = 1, missing do
      groups[#groups + 1] = 0
    end
    for _, g in ipairs(tail) do
      groups[#groups + 1] = g
    end
  else
    groups = {}
    if not parse_groups(s, groups, true) or #groups ~= 8 then
      return nil
    end
  end
  local out = {}
  for i = 1, 8 do
    local g = groups[i]
    out[2 * i - 1] = floor(g / 256)
    out[2 * i] = g % 256
  end
  return out
end

_M.parse_ipv4 = parse_ipv4
_M.parse_ipv6 = parse_ipv6

local function is_v4_mapped(b)
  for i = 1, 10 do
    if b[i] ~= 0 then
      return false
    end
  end
  return b[11] == 255 and b[12] == 255
end

-- Parses an address as returned by Kong (`kong.client.get_forwarded_ip()`).
-- IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are normalised to IPv4, since
-- IPGeolocation.io databases do not consistently alias that range.
-- Returns bytes, length (4 or 16), canonical text; or nil.
function _M.parse(ip)
  if type(ip) ~= "string" then
    return nil
  end
  local n = #ip
  if n < 2 or n > 64 then
    return nil
  end
  if find(ip, ":", 1, true) then
    if sub(ip, 1, 1) == "[" and sub(ip, -1) == "]" then
      ip = sub(ip, 2, -2)
    end
    local b = parse_ipv6(ip)
    if not b then
      return nil
    end
    if is_v4_mapped(b) then
      local v4 = { b[13], b[14], b[15], b[16] }
      return v4, 4, concat(v4, ".")
    end
    local zone = find(ip, "%", 1, true)
    if zone then
      ip = sub(ip, 1, zone - 1)
    end
    return b, 16, lower(ip)
  end
  local b = parse_ipv4(ip)
  if not b then
    return nil
  end
  return b, 4, ip
end

-- Loopback, link-local, private (RFC 1918 / RFC 4193), carrier-grade NAT,
-- link-local multicast and unspecified addresses. Mirrors the definition used
-- by the IPGeolocation.io Traefik plugin.
function _M.is_private(b, n)
  if n == 4 then
    local a, b2 = b[1], b[2]
    if a == 10 or a == 127 then return true end
    if a == 172 and b2 >= 16 and b2 <= 31 then return true end
    if a == 192 and b2 == 168 then return true end
    if a == 169 and b2 == 254 then return true end
    if a == 100 and b2 >= 64 and b2 <= 127 then return true end
    if a == 224 and b2 == 0 and b[3] == 0 then return true end
    if a == 0 and b2 == 0 and b[3] == 0 and b[4] == 0 then return true end
    return false
  end
  local first = b[1]
  if first == 0xfc or first == 0xfd then return true end                     -- fc00::/7
  if first == 0xfe and b[2] >= 0x80 and b[2] <= 0xbf then return true end    -- fe80::/10
  if first == 0xff and b[2] % 16 == 2 then return true end                   -- ff02::/16 (link-local multicast)
  if first == 0 then
    for i = 2, 15 do
      if b[i] ~= 0 then return false end
    end
    return b[16] == 0 or b[16] == 1                                          -- :: and ::1
  end
  return false
end

-- Parses "a.b.c.d", "a.b.c.d/n", "x::y" or "x::/n". Returns a CIDR object.
function _M.parse_cidr(s)
  if type(s) ~= "string" then
    return nil, "not a string"
  end
  local addr, len = match(s, "^([^/]+)/(%d+)$")
  if not addr then
    addr = s
  end
  local b, n = _M.parse(addr)
  if not b then
    return nil, "invalid address"
  end
  local max = n * 8
  local prefix = len and tonumber(len) or max
  if find(addr, ":", 1, true) and n == 4 then
    -- IPv4-mapped notation: translate the prefix to IPv4 bits.
    if not len then
      prefix = 32
    elseif prefix < 96 then
      return nil, "IPv4-mapped prefix shorter than /96"
    else
      prefix = prefix - 96
    end
  end
  if prefix > max then
    return nil, "prefix length out of range"
  end
  return { bytes = b, n = n, prefix = prefix }
end

function _M.cidr_match(cidr, b, n)
  if cidr.n ~= n then
    return false
  end
  local prefix = cidr.prefix
  local cb = cidr.bytes
  local full = floor(prefix / 8)
  for i = 1, full do
    if cb[i] ~= b[i] then
      return false
    end
  end
  local rem = prefix % 8
  if rem == 0 then
    return true
  end
  local div = 2 ^ (8 - rem)
  return floor(cb[full + 1] / div) == floor(b[full + 1] / div)
end

function _M.any_match(cidrs, b, n)
  for i = 1, #cidrs do
    if _M.cidr_match(cidrs[i], b, n) then
      return true
    end
  end
  return false
end

return _M
