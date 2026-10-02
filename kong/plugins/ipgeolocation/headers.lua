-- Request header handling.
--
-- Spoofing protection: before anything else, every incoming request header in
-- the X-IPGeo- namespace is removed, whatever its case and whether it uses
-- dashes or underscores (Kong's nginx template enables
-- `underscores_in_headers`, and CGI/WSGI-style backends fold "_" into "-").
-- Custom header names mapped in the configuration are removed the same way.
-- This happens for every request, including private and exempt addresses,
-- and including headers the current configuration does not set, so a backend
-- can trust any X-IPGeo-* header it receives.
--
-- All headers are enumerated (`ngx.req.get_headers(0)`), so a client cannot
-- hide a spoofed header behind the default 100-header parsing limit.

local fields = require "kong.plugins.ipgeolocation.fields"

local pairs, ipairs, type = pairs, ipairs, type
local lower, sub, find, gsub, byte = string.lower, string.sub, string.find, string.gsub, string.byte

local NAMESPACE = lower(fields.HEADER_PREFIX)   -- "x-ipgeo-"
local NAMESPACE_LEN = #NAMESPACE

local _M = {}

local function is_managed(name, managed)
  local folded = lower(name)
  if find(folded, "_", 1, true) then
    folded = gsub(folded, "_", "-")
  end
  if sub(folded, 1, NAMESPACE_LEN) == NAMESPACE then
    return true
  end
  return managed ~= nil and managed[folded] == true
end
_M.is_managed = is_managed

-- Removes every managed header from the request to the upstream.
function _M.strip(plan)
  local headers = ngx.req.get_headers(0)
  local managed = plan and plan.managed
  local clear = kong.service.request.clear_header
  for name in pairs(headers) do
    if type(name) == "string" and is_managed(name, managed) then
      clear(name)
    end
  end
end

-- Truncates to at most `max` bytes without splitting a UTF-8 sequence.
local function truncate(s, max)
  if #s <= max then
    return s
  end
  local cut = max
  for _ = 1, 4 do
    local c = byte(s, cut + 1)
    if not c or c < 0x80 or c >= 0xC0 then
      break
    end
    cut = cut - 1
  end
  return sub(s, 1, cut)
end

-- Header values never carry control characters (CR, LF, NUL, ...), even if a
-- database contains them, and are capped in length.
function _M.sanitize(value, max)
  if find(value, "%c") then
    value = gsub(value, "%c", "")
  end
  return truncate(value, max or 1024)
end

-- Sets the configured headers. Returns the names that were set.
function _M.apply(plan, values, texts, ip)
  local set_header = kong.service.request.set_header
  local true_value, false_value, max = plan.true_value, plan.false_value, plan.max_len
  local set = {}
  for _, h in ipairs(plan.headers) do
    local field, v = h.field, nil
    if field == fields.IP_FIELD then
      v = ip
    else
      local tv = values[field]
      if tv == true then
        v = true_value
      elseif tv == false then
        v = false_value
      elseif tv ~= nil then
        v = texts[field]
      end
    end
    if type(v) == "string" and v ~= "" then
      v = _M.sanitize(v, max)
      if v ~= "" then
        set_header(h.name, v)
        set[#set + 1] = h.name
      end
    end
  end
  return set
end

function _M.clear(names)
  local clear = kong.service.request.clear_header
  for i = 1, #names do
    clear(names[i])
  end
end

return _M
