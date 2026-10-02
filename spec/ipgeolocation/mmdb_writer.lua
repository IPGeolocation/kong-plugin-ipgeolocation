-- A small MaxMind DB writer used only by the test suite to generate
-- deterministic fixtures. It is intentionally independent from the reader in
-- kong/plugins/ipgeolocation/mmdb.lua; its output was verified against
-- python-maxminddb during development.
--
--   local W = require "spec.ipgeolocation.mmdb_writer"
--   local w = W.new({ record_size = 28 })
--   w:insert("203.0.113.0/24", { location = { country = { code2 = "PK" } } })
--   w:write("/tmp/fixture.mmdb")
--
-- Lua values map to MMDB types: strings -> utf8_string, booleans -> boolean,
-- integers 0..2^32-1 -> uint32, other numbers -> double, tables with keys ->
-- map. Use the wrappers below for explicit types, W.array() for arrays
-- (including empty ones), and W.raw() / W.pointer() to craft invalid data.

local ffi = require "ffi"
local iputil = require "kong.plugins.ipgeolocation.iputil"

local char, byte, rep = string.char, string.byte, string.rep
local floor = math.floor
local concat, sort = table.concat, table.sort

local W = {}

local function typed(t, v) return { __mmdb = t, v = v } end
function W.uint16(v) return typed("uint16", v) end
function W.uint32(v) return typed("uint32", v) end
function W.uint64(v) return typed("uint64", v) end
function W.uint128(v) return typed("uint128", v) end
function W.int32(v) return typed("int32", v) end
function W.double(v) return typed("double", v) end
function W.float(v) return typed("float", v) end
function W.bytes(v) return typed("bytes", v) end
function W.array(t) return typed("array", t or {}) end
function W.map(t) return typed("map", t or {}) end
function W.raw(s) return typed("raw", s) end          -- bytes emitted verbatim
function W.pointer(p) return typed("pointer", p) end  -- pointer to data-section offset p

local function be_bytes(v, n)
  local out = {}
  for i = n, 1, -1 do
    out[i] = char(v % 256)
    v = floor(v / 256)
  end
  return concat(out)
end

local function uint_bytes(v)
  if v == 0 then return "" end
  local out = {}
  while v > 0 do
    out[#out + 1] = char(v % 256)
    v = floor(v / 256)
  end
  local r = {}
  for i = #out, 1, -1 do r[#r + 1] = out[i] end
  return concat(r)
end

local function ctrl(typ, size)
  local bits, extra
  if size < 29 then
    bits, extra = size, ""
  elseif size < 285 then
    bits, extra = 29, char(size - 29)
  elseif size < 65821 then
    bits, extra = 30, be_bytes(size - 285, 2)
  else
    bits, extra = 31, be_bytes(size - 65821, 3)
  end
  if typ <= 7 then
    return char(typ * 32 + bits) .. extra
  end
  return char(bits) .. char(typ - 7) .. extra
end

function W.pointer_bytes(p)
  if p < 2048 then
    return char(0x20 + floor(p / 256)) .. char(p % 256)
  elseif p < 526336 then
    local v = p - 2048
    return char(0x28 + floor(v / 65536)) .. be_bytes(v % 65536, 2)
  elseif p < 134744064 then
    local v = p - 526336
    return char(0x30 + floor(v / 16777216)) .. be_bytes(v % 16777216, 3)
  end
  return char(0x38) .. be_bytes(p, 4)
end

local dbl = ffi.new("union { uint8_t b[8]; double v; }")
local flt = ffi.new("union { uint8_t b[4]; float v; }")
local LE = ffi.abi("le")

local function double_bytes(v)
  dbl.v = v
  local out = {}
  for i = 0, 7 do out[#out + 1] = char(dbl.b[LE and (7 - i) or i]) end
  return concat(out)
end

local function float_bytes(v)
  flt.v = v
  local out = {}
  for i = 0, 3 do out[#out + 1] = char(flt.b[LE and (3 - i) or i]) end
  return concat(out)
end

---------------------------------------------------------------------------
-- Data section encoder with pointer deduplication of keys and strings
---------------------------------------------------------------------------

local Data = {}
Data.__index = Data

local function new_data(base_offset, dedupe)
  return setmetatable({ parts = {}, len = 0, base = base_offset or 0, seen = {}, dedupe = dedupe }, Data)
end

function Data:emit(s)
  self.parts[#self.parts + 1] = s
  self.len = self.len + #s
end

function Data:offset()
  return self.base + self.len
end

function Data:string(s, kind)
  local key = (kind or "s") .. s
  if self.dedupe and #s >= 3 and self.seen[key] then
    return self:emit(W.pointer_bytes(self.seen[key]))
  end
  if self.dedupe and #s >= 3 then
    self.seen[key] = self:offset()
  end
  self:emit(ctrl(kind == "b" and 4 or 2, #s) .. s)
end

function Data:value(v)
  local t = type(v)
  if t == "string" then
    return self:string(v)
  elseif t == "boolean" then
    return self:emit(ctrl(14, v and 1 or 0))
  elseif t == "number" then
    if v >= 0 and v == floor(v) and v < 4294967296 then
      return self:emit(ctrl(6, #uint_bytes(v)) .. uint_bytes(v))
    end
    return self:emit(ctrl(3, 8) .. double_bytes(v))
  elseif t ~= "table" then
    error("cannot encode " .. t)
  end

  local mt = v.__mmdb
  if mt == "raw" then
    return self:emit(v.v)
  elseif mt == "pointer" then
    return self:emit(W.pointer_bytes(v.v))
  elseif mt == "uint16" then
    return self:emit(ctrl(5, #uint_bytes(v.v)) .. uint_bytes(v.v))
  elseif mt == "uint32" then
    return self:emit(ctrl(6, #uint_bytes(v.v)) .. uint_bytes(v.v))
  elseif mt == "uint64" then
    return self:emit(ctrl(9, #uint_bytes(v.v)) .. uint_bytes(v.v))
  elseif mt == "uint128" then
    return self:emit(ctrl(10, #uint_bytes(v.v)) .. uint_bytes(v.v))
  elseif mt == "int32" then
    local n = v.v
    if n < 0 then
      return self:emit(ctrl(8, 4) .. be_bytes(n + 4294967296, 4))
    end
    return self:emit(ctrl(8, #uint_bytes(n)) .. uint_bytes(n))
  elseif mt == "double" then
    return self:emit(ctrl(3, 8) .. double_bytes(v.v))
  elseif mt == "float" then
    return self:emit(ctrl(15, 4) .. float_bytes(v.v))
  elseif mt == "bytes" then
    return self:string(v.v, "b")
  elseif mt == "array" then
    local a = v.v
    self:emit(ctrl(11, #a))
    for i = 1, #a do self:value(a[i]) end
    return
  end

  local m = mt == "map" and v.v or v
  local keys = {}
  for k in pairs(m) do keys[#keys + 1] = k end
  sort(keys)
  self:emit(ctrl(7, #keys))
  for _, k in ipairs(keys) do
    self:string(k, "k")
    self:value(m[k])
  end
end

function Data:bytes()
  return concat(self.parts)
end

---------------------------------------------------------------------------
-- Writer
---------------------------------------------------------------------------

local Writer = {}
Writer.__index = Writer

function W.new(opts)
  opts = opts or {}
  return setmetatable({
    ip_version = opts.ip_version or 6,
    record_size = opts.record_size or 32,
    database_type = opts.database_type or "ipgeolocation.io Test Database",
    languages = opts.languages or { "en" },
    description = opts.description or { en = "Synthetic test fixture" },
    build_epoch = opts.build_epoch or 1790000000,
    alias_ipv4_mapped = opts.alias_ipv4_mapped or false,
    data_padding = opts.data_padding or 0,
    dedupe = opts.dedupe ~= false,
    metadata_override = opts.metadata,
    root = {},
    nets = {},
  }, Writer)
end

local function bit_at(bytes, i) -- 0-based bit index
  local b = bytes[floor(i / 8) + 1]
  return floor(b / 2 ^ (7 - i % 8)) % 2
end

function Writer:insert(cidr, value)
  local c = assert(iputil.parse_cidr(cidr), "invalid network " .. tostring(cidr))
  local bytes, prefix = c.bytes, c.prefix
  if c.n == 4 and self.ip_version == 6 then
    local v6 = {}
    for i = 1, 12 do v6[i] = 0 end
    for i = 1, 4 do v6[12 + i] = bytes[i] end
    bytes, prefix = v6, prefix + 96
  elseif c.n == 16 and self.ip_version == 4 then
    error("IPv6 network in an IPv4 database")
  end
  self.nets[#self.nets + 1] = { bytes = bytes, prefix = prefix, value = value }
end

local function place(root, net)
  local node = root
  for i = 0, net.prefix - 1 do
    local b = bit_at(net.bytes, i)
    if node.leaf then
      -- Split a less specific network to make room for this one.
      node[0] = { leaf = true, value = node.value }
      node[1] = { leaf = true, value = node.value }
      node.leaf, node.value = nil, nil
    end
    local child = node[b]
    if not child then
      child = {}
      node[b] = child
    end
    node = child
  end
  node[0], node[1] = nil, nil
  node.leaf, node.value = true, net.value
end

local function node_at(root, bits)
  local node = root
  for _, b in ipairs(bits) do
    if not node or node.leaf then return nil end
    local child = node[b]
    if not child then
      child = {}
      node[b] = child
    end
    node = child
  end
  return node
end

function Writer:build()
  -- Least specific first so that more specific networks split them.
  sort(self.nets, function(a, b) return a.prefix < b.prefix end)
  local root = {}
  for _, net in ipairs(self.nets) do place(root, net) end

  if self.alias_ipv4_mapped and self.ip_version == 6 then
    local v4bits, mapbits = {}, {}
    for i = 1, 96 do v4bits[i] = 0 end
    for i = 1, 80 do mapbits[i] = 0 end
    for i = 81, 96 do mapbits[i] = 1 end
    local v4root = node_at(root, v4bits)
    local parentbits = {}
    for i = 1, 95 do parentbits[i] = mapbits[i] end
    local parent = node_at(root, parentbits)
    if v4root and parent then
      parent[1] = v4root
    end
  end

  -- Number internal nodes breadth-first (shared subtrees numbered once).
  local order, number, queue, head = {}, {}, { root }, 1
  while queue[head] do
    local node = queue[head]
    head = head + 1
    if not node.leaf and not number[node] then
      order[#order + 1] = node
      number[node] = #order - 1
      for b = 0, 1 do
        local child = node[b]
        if child and not child.leaf and (child[0] or child[1]) and not number[child] then
          queue[#queue + 1] = child
        end
      end
    end
  end
  return root, order, number
end

local function record_bytes(size, left, right)
  if size == 24 then
    return be_bytes(left, 3) .. be_bytes(right, 3)
  elseif size == 28 then
    return be_bytes(left % 16777216, 3)
           .. char(floor(left / 16777216) * 16 + floor(right / 16777216))
           .. be_bytes(right % 16777216, 3)
  end
  return be_bytes(left, 4) .. be_bytes(right, 4)
end

function Writer:serialize()
  local _, order, number = self:build()
  local node_count = #order
  if node_count == 0 then
    -- A database needs at least one node.
    order = { {} }
    number = { [order[1]] = 0 }
    node_count = 1
  end

  -- Data section: one entry per distinct record value (by identity).
  local data = new_data(self.data_padding, self.dedupe)
  local offsets = {}
  local function data_offset(value)
    local off = offsets[value]
    if not off then
      off = data:offset()
      offsets[value] = off
      data:value(value)
    end
    return off
  end

  local max = 2 ^ self.record_size - 1
  local tree = {}
  for _, node in ipairs(order) do
    local rec = {}
    for b = 0, 1 do
      local child = node[b]
      local v
      if not child or (not child.leaf and not (child[0] or child[1])) then
        v = node_count
      elseif child.leaf then
        if child.value == nil then
          v = node_count
        else
          v = node_count + 16 + data_offset(child.value)
        end
      else
        v = number[child]
      end
      assert(v <= max, "record value does not fit the record size")
      rec[b] = v
    end
    tree[#tree + 1] = record_bytes(self.record_size, rec[0], rec[1])
  end

  local md = self.metadata_override or {
    node_count = W.uint32(node_count),
    record_size = W.uint16(self.record_size),
    ip_version = W.uint16(self.ip_version),
    database_type = self.database_type,
    languages = W.array(self.languages),
    binary_format_major_version = W.uint16(2),
    binary_format_minor_version = W.uint16(0),
    build_epoch = W.uint64(self.build_epoch),
    description = self.description,
  }
  local mdata = new_data(0, false)
  mdata:value(md)

  return concat(tree), data:bytes(), "\171\205\239MaxMind.com" .. mdata:bytes(), node_count
end

function Writer:write(path)
  local tree, data, meta = self:serialize()
  local f = assert(io.open(path, "wb"))
  f:write(tree, rep("\0", 16))
  if self.data_padding > 0 then
    -- Sparse hole: no disk space is used for the padding.
    f:seek("cur", self.data_padding)
  end
  f:write(data, meta)
  f:close()
  return path
end

-- Writes bytes as-is (for corrupted fixtures).
function W.write_bytes(path, s)
  local f = assert(io.open(path, "wb"))
  f:write(s)
  f:close()
  return path
end

function W.read_bytes(path)
  local f = assert(io.open(path, "rb"))
  local s = f:read("*a")
  f:close()
  return s
end

W.ctrl = ctrl
W.byte = byte

return W
