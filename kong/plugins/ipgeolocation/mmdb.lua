-- A small, bounds-checked MaxMind DB (MMDB, binary format 2.x) reader for
-- LuaJIT / OpenResty, written for IPGeolocation.io databases.
--
-- Design
--   * The file is mapped read-only with mmap(2) through the LuaJIT FFI. No
--     native library beyond libc is needed, and every worker that maps the
--     same file shares one copy of it in the kernel page cache. This matters:
--     IPGeolocation.io Security and Location databases are several GiB.
--   * Every byte access is bounds-checked against the section it belongs to.
--     A corrupt or hostile database produces an error, never a read outside
--     the mapping.
--   * File offsets are plain Lua numbers (doubles) and are never passed
--     through the 32-bit `bit.*` operations, because offsets exceed 2^31.
--   * Records are not decoded wholesale. `extract` walks one record along a
--     precompiled trie of wanted key paths, skipping everything else without
--     allocating. Work and memory per call are capped by budgets.
--
-- The file must never be modified in place while mapped (truncating a mapped
-- file can raise SIGBUS). Replace databases atomically: write a temporary
-- file in the same directory, then rename(2) it over the old one.

local ffi = require "ffi"
local bit = require "bit"

local C = ffi.C
local band, bor, rshift = bit.band, bit.bor, bit.rshift
local ffi_string, ffi_cast, ffi_new, ffi_gc = ffi.string, ffi.cast, ffi.new, ffi.gc
local floor = math.floor
local huge = math.huge
local type, tonumber, tostring, pcall, setmetatable = type, tonumber, tostring, pcall, setmetatable
local str_find = string.find

local function cdef(decl)
  -- Another module may already have declared the same libc symbol; LuaJIT
  -- refuses redefinitions, in which case the existing declaration is used.
  pcall(ffi.cdef, decl)
end

cdef("int open(const char *pathname, int flags, ...);")
cdef("int close(int fd);")
cdef("int64_t lseek(int fd, int64_t offset, int whence);")
cdef("void *mmap(void *addr, size_t length, int prot, int flags, int fd, int64_t offset);")
cdef("int munmap(void *addr, size_t length);")
cdef("int memcmp(const void *s1, const void *s2, size_t n);")
cdef("char *strerror(int errnum);")

local O_RDONLY, O_NONBLOCK, O_CLOEXEC = 0, 0, 0
if ffi.os == "Linux" then
  O_NONBLOCK, O_CLOEXEC = 0x800, 0x80000
elseif ffi.os == "OSX" then
  O_NONBLOCK, O_CLOEXEC = 0x4, 0x1000000
elseif ffi.os == "BSD" then
  O_NONBLOCK, O_CLOEXEC = 0x4, 0x100000
end
local OPEN_FLAGS = bor(O_RDONLY, O_NONBLOCK, O_CLOEXEC)
local PROT_READ, MAP_SHARED, SEEK_END = 1, 1, 2

local METADATA_MARKER = "\171\205\239MaxMind.com"
local METADATA_SCAN = 128 * 1024
local MIN_FILE_SIZE = 16 + #METADATA_MARKER + 1
local MAX_DEPTH = 32

-- Per-operation budgets. Operations never yield, so module-level counters
-- are safe inside one OpenResty worker.
local EXTRACT_STEPS, EXTRACT_BYTES, EXTRACT_MAX_STRING = 20000, 262144, 16384
local RECORD_STEPS, RECORD_BYTES = 1000000, 64 * 1024 * 1024
local METADATA_STEPS, METADATA_BYTES = 100000, 1024 * 1024
local MAX_ARRAY_ITEMS = 256

local steps, bytes_left, max_string = 0, 0, huge

-- Metatable attached to decoded arrays so callers can tell an empty array
-- from an empty map.
local ARRAY_MT = { __name = "mmdb.array" }

local ERR_IPV6_IN_IPV4 = "IPv6 lookup in an IPv4-only database"

local _M = { _VERSION = "0.1.0", array_mt = ARRAY_MT, ERR_IPV6_IN_IPV4 = ERR_IPV6_IN_IPV4 }

local function errstr(errno)
  local s = C.strerror(errno)
  if s == nil then
    return "errno " .. tostring(errno)
  end
  return ffi_string(s)
end

local LITTLE_ENDIAN = ffi.abi("le")
local dbl = ffi_new("union { uint8_t b[8]; double v; }")
local flt = ffi_new("union { uint8_t b[4]; float v; }")

local function read_double(d, p)
  if LITTLE_ENDIAN then
    for i = 0, 7 do dbl.b[7 - i] = d[p + i] end
  else
    for i = 0, 7 do dbl.b[i] = d[p + i] end
  end
  return tonumber(dbl.v)
end

local function read_float(d, p)
  if LITTLE_ENDIAN then
    for i = 0, 3 do flt.b[3 - i] = d[p + i] end
  else
    for i = 0, 3 do flt.b[i] = d[p + i] end
  end
  return tonumber(flt.v)
end

local function read_uint(d, p, size)
  local v = 0
  for i = 0, size - 1 do
    v = v * 256 + d[p + i]
  end
  return v
end

-- Maximum payload size per scalar type (nil: any size).
local SCALAR_MAX = {
  [2] = nil,   -- utf8 string
  [3] = 8,     -- double (must be exactly 8)
  [4] = nil,   -- bytes
  [5] = 2,     -- uint16
  [6] = 4,     -- uint32
  [8] = 4,     -- int32
  [9] = 8,     -- uint64
  [10] = 16,   -- uint128
  [15] = 4,    -- float (must be exactly 4)
}

-- Reads a control byte. Returns type, size, payload offset. For pointers the
-- second value is the raw control byte, because pointers encode their size
-- differently.
local function read_ctrl(d, off, limit)
  if off >= limit or off < 0 then
    return nil, "offset outside data section"
  end
  local ctrl = d[off]
  off = off + 1
  local typ = rshift(ctrl, 5)
  if typ == 1 then
    return 1, ctrl, off
  end
  if typ == 0 then
    if off >= limit then
      return nil, "truncated extended type"
    end
    typ = 7 + d[off]
    off = off + 1
    if typ < 8 or typ > 15 then
      return nil, "invalid extended type"
    end
  end
  local size = band(ctrl, 0x1f)
  if size >= 29 then
    if size == 29 then
      if off + 1 > limit then return nil, "truncated size" end
      size = 29 + d[off]
      off = off + 1
    elseif size == 30 then
      if off + 2 > limit then return nil, "truncated size" end
      size = 285 + d[off] * 256 + d[off + 1]
      off = off + 2
    else
      if off + 3 > limit then return nil, "truncated size" end
      size = 65821 + d[off] * 65536 + d[off + 1] * 256 + d[off + 2]
      off = off + 3
    end
  end
  return typ, size, off
end

-- Returns the pointer value (relative to the section base) and the offset
-- after the pointer bytes.
local function read_pointer(d, ctrl, p, limit)
  local ss = band(rshift(ctrl, 3), 3)
  local vvv = band(ctrl, 7)
  if p + ss + 1 > limit then
    return nil, "truncated pointer"
  end
  local v
  if ss == 0 then
    v = vvv * 256 + d[p]
  elseif ss == 1 then
    v = 2048 + vvv * 65536 + d[p] * 256 + d[p + 1]
  elseif ss == 2 then
    v = 526336 + vvv * 16777216 + d[p] * 65536 + d[p + 1] * 256 + d[p + 2]
  else
    v = d[p] * 16777216 + d[p + 1] * 65536 + d[p + 2] * 256 + d[p + 3]
  end
  return v, p + ss + 1
end

-- Resolves a pointer to its target control byte. Returns typ, size, payload
-- offset of the target, plus the offset following the pointer itself.
local function follow(d, ctrl, p, base, limit)
  local ptr, after = read_pointer(d, ctrl, p, limit)
  if not ptr then
    return nil, after
  end
  local target = base + ptr
  if target >= limit then
    return nil, "pointer outside data section"
  end
  local typ, size, tp = read_ctrl(d, target, limit)
  if not typ then
    return nil, size
  end
  if typ == 1 then
    return nil, "pointer to pointer"
  end
  return typ, size, tp, after, target
end

local function check_scalar(typ, size)
  if typ == 12 or typ == 13 then
    return nil, "unexpected container or end marker"
  end
  if typ == 3 and size ~= 8 then
    return nil, "invalid double size"
  end
  if typ == 15 and size ~= 4 then
    return nil, "invalid float size"
  end
  local max = SCALAR_MAX[typ]
  if max and size > max then
    return nil, "invalid integer size"
  end
  return true
end

local function charge(n)
  steps = steps - 1
  if steps < 0 then
    return nil, "record exceeds decoding budget"
  end
  if n then
    bytes_left = bytes_left - n
    if bytes_left < 0 then
      return nil, "record exceeds size budget"
    end
  end
  return true
end

-- Skips the value at `off`, returning the offset that follows it.
local function skip(d, off, limit, depth)
  if depth > MAX_DEPTH then
    return nil, "data nested too deeply"
  end
  local ok, err = charge()
  if not ok then return nil, err end
  local typ, size, p = read_ctrl(d, off, limit)
  if not typ then
    return nil, size
  end
  if typ == 1 then
    local nxt = p + band(rshift(size, 3), 3) + 1
    if nxt > limit then
      return nil, "truncated pointer"
    end
    return nxt
  elseif typ == 7 then
    for _ = 1, size do
      p, err = skip(d, p, limit, depth + 1)
      if not p then return nil, err end
      p, err = skip(d, p, limit, depth + 1)
      if not p then return nil, err end
    end
    return p
  elseif typ == 11 then
    for _ = 1, size do
      p, err = skip(d, p, limit, depth + 1)
      if not p then return nil, err end
    end
    return p
  elseif typ == 14 then
    if size > 1 then
      return nil, "invalid boolean"
    end
    return p
  end
  ok, err = check_scalar(typ, size)
  if not ok then return nil, err end
  if p + size > limit then
    return nil, "value exceeds data section"
  end
  return p + size
end

-- Fully decodes the value at `off`. Returns next offset and value; on error
-- returns nil and a message.
local function decode(d, off, base, limit, depth)
  if depth > MAX_DEPTH then
    return nil, "data nested too deeply"
  end
  local ok, err = charge()
  if not ok then return nil, err end
  local typ, size, p = read_ctrl(d, off, limit)
  if not typ then
    return nil, size
  end
  if typ == 1 then
    local ptr, after = read_pointer(d, size, p, limit)
    if not ptr then return nil, after end
    local target = base + ptr
    if target >= limit then
      return nil, "pointer outside data section"
    end
    if rshift(d[target], 5) == 1 then
      return nil, "pointer to pointer"
    end
    local nxt, v = decode(d, target, base, limit, depth + 1)
    if not nxt then return nil, v end
    return after, v
  end

  if typ == 2 or typ == 4 then
    if p + size > limit then
      return nil, "string exceeds data section"
    end
    local n = size < max_string and size or max_string
    ok, err = charge(n)
    if not ok then return nil, err end
    return p + size, ffi_string(d + p, n)
  elseif typ == 7 then
    local t = {}
    for _ = 1, size do
      local k, v
      p, k = decode(d, p, base, limit, depth + 1)
      if not p then return nil, k end
      if type(k) ~= "string" then
        return nil, "map key is not a string"
      end
      p, v = decode(d, p, base, limit, depth + 1)
      if not p then return nil, v end
      t[k] = v
    end
    return p, t
  elseif typ == 11 then
    local t = setmetatable({}, ARRAY_MT)
    for i = 1, size do
      local v
      p, v = decode(d, p, base, limit, depth + 1)
      if not p then return nil, v end
      t[i] = v
    end
    return p, t
  elseif typ == 14 then
    if size > 1 then
      return nil, "invalid boolean"
    end
    return p, size == 1
  end

  ok, err = check_scalar(typ, size)
  if not ok then return nil, err end
  if p + size > limit then
    return nil, "value exceeds data section"
  end
  if typ == 3 then
    return p + 8, read_double(d, p)
  elseif typ == 15 then
    return p + 4, read_float(d, p)
  elseif typ == 8 then
    local v = read_uint(d, p, size)
    if size == 4 and v >= 2147483648 then
      v = v - 4294967296
    end
    return p + size, v
  end
  -- uint16, uint32, uint64, uint128 (values above 2^53 lose precision)
  return p + size, read_uint(d, p, size)
end

-- Decodes a value for a leaf of the extraction trie: scalars as Lua values,
-- arrays as capped lists of scalars, maps as nil (handled by the walker).
local function decode_leaf(d, off, base, limit, depth)
  if depth > MAX_DEPTH then
    return nil, "data nested too deeply"
  end
  local typ, size, p = read_ctrl(d, off, limit)
  if not typ then
    return nil, size
  end
  if typ == 1 then
    local ptr, after = read_pointer(d, size, p, limit)
    if not ptr then return nil, after end
    local target = base + ptr
    if target >= limit then
      return nil, "pointer outside data section"
    end
    if rshift(d[target], 5) == 1 then
      return nil, "pointer to pointer"
    end
    local nxt, v = decode_leaf(d, target, base, limit, depth + 1)
    if not nxt then return nil, v end
    return after, v
  end
  if typ == 11 then
    local ok, err = charge()
    if not ok then return nil, err end
    local list, n = setmetatable({}, ARRAY_MT), 0
    for _ = 1, size do
      if n >= MAX_ARRAY_ITEMS then
        p, err = skip(d, p, limit, depth + 1)
        if not p then return nil, err end
      else
        local v
        p, v = decode_leaf(d, p, base, limit, depth + 1)
        if not p then return nil, v end
        local tv = type(v)
        if tv == "string" or tv == "number" or tv == "boolean" then
          n = n + 1
          list[n] = v
        end
      end
    end
    return p, list
  end
  if typ == 7 then
    local nxt, err = skip(d, off, limit, depth)
    if not nxt then return nil, err end
    return nxt, nil
  end
  return decode(d, off, base, limit, depth)
end

-- Reads a map key. Returns payload offset, length, and the offset after the
-- key (keys are usually pointers to shared strings).
local function read_key(d, p, base, limit)
  local ok, err = charge()
  if not ok then return nil, err end
  local typ, size, kp = read_ctrl(d, p, limit)
  if not typ then
    return nil, size
  end
  local after
  if typ == 1 then
    local t2, s2, p2, a2 = follow(d, size, kp, base, limit)
    if not t2 then return nil, s2 end
    typ, size, kp, after = t2, s2, p2, a2
  end
  if typ ~= 2 then
    return nil, "map key is not a string"
  end
  if kp + size > limit then
    return nil, "map key exceeds data section"
  end
  return kp, size, after or (kp + size)
end

local function key_matches(d, kp, klen, len, first, buf)
  return len == klen and d[kp] == first and (klen == 1 or C.memcmp(d + kp, buf, klen) == 0)
end

-- Walks the value at `off` along trie `node`, storing leaf values into
-- `out[slot]`. Returns the offset following the value.
local function walk(d, off, base, limit, node, out, lang, depth)
  if depth > MAX_DEPTH then
    return nil, "data nested too deeply"
  end
  local ok, err = charge()
  if not ok then return nil, err end
  local typ, size, p = read_ctrl(d, off, limit)
  if not typ then
    return nil, size
  end
  local after
  if typ == 1 then
    local t2, s2, p2, a2, target = follow(d, size, p, base, limit)
    if not t2 then return nil, s2 end
    typ, size, p, after, off = t2, s2, p2, a2, target
  end

  local slots = node.slots

  if typ ~= 7 then
    if slots then
      local nxt, v = decode_leaf(d, off, base, limit, depth)
      if not nxt then return nil, v end
      if v ~= nil then
        for i = 1, #slots do
          out[slots[i]] = v
        end
      end
      return after or nxt
    end
    if after then
      return after
    end
    return skip(d, off, limit, depth)
  end

  local n = node.n
  local keys_len, keys_first, keys_buf, kids = node.lens, node.first, node.bufs, node.kids
  local lang_len, lang_first, lang_buf = lang.len, lang.first, lang.buf
  local lang_val, en_val

  for _ = 1, size do
    local kp, klen, nxt = read_key(d, p, base, limit)
    if not kp then return nil, klen end
    p = nxt
    local vstart = p
    local consumed = false

    for ci = 1, n do
      if key_matches(d, kp, klen, keys_len[ci], keys_first[ci], keys_buf[ci]) then
        p, err = walk(d, vstart, base, limit, kids[ci], out, lang, depth + 1)
        if not p then return nil, err end
        consumed = true
        break
      end
    end

    if slots and (klen == lang_len or klen == 2) then
      -- Localised value: the configured language first, English second.
      local which
      if key_matches(d, kp, klen, lang_len, lang_first, lang_buf) then
        which = 1
      elseif klen == 2 and d[kp] == 101 and d[kp + 1] == 110 then -- "en"
        which = 2
      end
      if which then
        local e, v = decode_leaf(d, vstart, base, limit, depth + 1)
        if not e then return nil, v end
        local tv = type(v)
        if tv == "string" or tv == "number" then
          if which == 1 then lang_val = v else en_val = v end
        end
        if not consumed then
          p = e
          consumed = true
        end
      end
    end

    if not consumed then
      p, err = skip(d, vstart, limit, depth + 1)
      if not p then return nil, err end
    end
  end

  if slots then
    local v = lang_val
    if v == nil or v == "" then
      v = en_val
    end
    if v ~= nil then
      for i = 1, #slots do
        out[slots[i]] = v
      end
    end
  end

  return after or p
end

---------------------------------------------------------------------------
-- Reader object
---------------------------------------------------------------------------

local Reader = {}
Reader.__index = Reader

local function is_uint(v)
  return type(v) == "number" and v >= 0 and v == floor(v) and v < 2^53
end

local function init(self)
  local d, size = self.data, self.size

  -- The metadata section starts after the last occurrence of the marker in
  -- the final 128 KiB of the file.
  local scan = size < METADATA_SCAN and size or METADATA_SCAN
  local tail_start = size - scan
  local tail = ffi_string(d + tail_start, scan)
  local pos, last = 1, nil
  while true do
    local s = str_find(tail, METADATA_MARKER, pos, true)
    if not s then break end
    last = s
    pos = s + 1
  end
  if not last then
    return nil, "metadata section not found (not an MMDB file)"
  end
  local marker_off = tail_start + last - 1
  local md_start = marker_off + #METADATA_MARKER

  steps, bytes_left, max_string = METADATA_STEPS, METADATA_BYTES, 4096
  local nxt, md = decode(d, md_start, md_start, size, 0)
  if not nxt then
    return nil, "invalid metadata: " .. tostring(md)
  end
  if type(md) ~= "table" then
    return nil, "invalid metadata: not a map"
  end

  local node_count = md.node_count
  local record_size = md.record_size
  local ip_version = md.ip_version
  local major = md.binary_format_major_version

  if major ~= 2 then
    return nil, "unsupported binary format version " .. tostring(major)
  end
  if not is_uint(node_count) or node_count < 1 then
    return nil, "invalid node_count in metadata"
  end
  if record_size ~= 24 and record_size ~= 28 and record_size ~= 32 then
    return nil, "unsupported record_size " .. tostring(record_size)
  end
  if ip_version ~= 4 and ip_version ~= 6 then
    return nil, "invalid ip_version " .. tostring(ip_version)
  end

  local node_bytes = record_size / 4
  local tree_size = node_count * node_bytes
  local data_start = tree_size + 16
  if data_start > marker_off then
    return nil, "search tree is larger than the file (corrupt metadata)"
  end
  for i = tree_size, tree_size + 15 do
    if d[i] ~= 0 then
      return nil, "data section separator missing (corrupt search tree or metadata)"
    end
  end

  self.node_count = node_count
  self.record_size = record_size
  self.node_bytes = node_bytes
  self.tree_size = tree_size
  self.data_start = data_start
  self.data_end = marker_off
  self.ip_version = ip_version

  local languages = {}
  if type(md.languages) == "table" then
    for _, l in ipairs(md.languages) do
      if type(l) == "string" then languages[#languages + 1] = l end
    end
  end
  self.metadata = {
    database_type = type(md.database_type) == "string" and md.database_type or "",
    description = type(md.description) == "table" and md.description or {},
    languages = languages,
    build_epoch = is_uint(md.build_epoch) and md.build_epoch or nil,
    ip_version = ip_version,
    record_size = record_size,
    node_count = node_count,
    binary_format_major_version = major,
    binary_format_minor_version = md.binary_format_minor_version,
  }

  -- IPv4 addresses live under ::/96 of an IPv6 tree. Find that node once.
  if ip_version == 6 then
    local node, i = 0, 0
    while i < 96 and node < node_count do
      node = self:_record(node, 0)
      i = i + 1
    end
    self.ipv4_start = node
  else
    self.ipv4_start = 0
  end

  return true
end

-- Opens and validates a database. Returns a reader, or nil, an error and
-- `true` when the error came from the operating system (permissions, file
-- descriptors, memory) rather than from the file's content, so that the
-- caller can retry it without waiting for the file to change.
function _M.open(path)
  if type(path) ~= "string" or path == "" then
    return nil, "invalid path"
  end
  local fd = C.open(path, OPEN_FLAGS)
  if fd < 0 then
    return nil, "cannot open file: " .. errstr(ffi.errno()), true
  end
  local size = tonumber(C.lseek(fd, 0, SEEK_END))
  if not size or size < 0 then
    local e = ffi.errno()
    C.close(fd)
    return nil, "cannot determine file size: " .. errstr(e), true
  end
  if size < MIN_FILE_SIZE then
    C.close(fd)
    return nil, "file is too small to be an MMDB database"
  end
  local p = C.mmap(nil, size, PROT_READ, MAP_SHARED, fd, 0)
  local map_errno = ffi.errno()
  C.close(fd)
  if ffi_cast("intptr_t", p) == -1 then
    return nil, "cannot map file: " .. errstr(map_errno), true
  end
  local map = ffi_gc(p, function(ptr) C.munmap(ptr, size) end)

  local self = setmetatable({
    path = path,
    size = size,
    _map = map,
    data = ffi_cast("const uint8_t *", map),
    closed = false,
  }, Reader)

  local ok, err = init(self)
  if not ok then
    self:close()
    return nil, err
  end
  return self
end

function Reader:_record(node, b)
  local d, base = self.data, node * self.node_bytes
  local rs = self.record_size
  if rs == 24 then
    local o = base + b * 3
    return d[o] * 65536 + d[o + 1] * 256 + d[o + 2]
  elseif rs == 28 then
    if b == 0 then
      return rshift(d[base + 3], 4) * 16777216 + d[base] * 65536 + d[base + 1] * 256 + d[base + 2]
    end
    return band(d[base + 3], 15) * 16777216 + d[base + 4] * 65536 + d[base + 5] * 256 + d[base + 6]
  end
  local o = base + b * 4
  return d[o] * 16777216 + d[o + 1] * 65536 + d[o + 2] * 256 + d[o + 3]
end

-- Looks up an address given as a table of 4 or 16 bytes (1-based).
-- Returns the absolute data offset of the record and the prefix length,
-- `false` and the prefix length when the address has no record, or nil and an
-- error message.
function Reader:lookup(ip, nbytes)
  if self.closed then
    return nil, "database is closed"
  end
  local node, bits
  if nbytes == 4 then
    node, bits = self.ipv4_start, 32
  elseif nbytes == 16 then
    if self.ip_version == 4 then
      return nil, ERR_IPV6_IN_IPV4
    end
    node, bits = 0, 128
  else
    return nil, "invalid address length"
  end

  local d, nb, rs, node_count = self.data, self.node_bytes, self.record_size, self.node_count
  local i = 0
  while i < bits and node < node_count do
    local b = band(rshift(ip[rshift(i, 3) + 1], 7 - band(i, 7)), 1)
    local base = node * nb
    if rs == 32 then
      local o = base + b * 4
      node = d[o] * 16777216 + d[o + 1] * 65536 + d[o + 2] * 256 + d[o + 3]
    elseif rs == 24 then
      local o = base + b * 3
      node = d[o] * 65536 + d[o + 1] * 256 + d[o + 2]
    elseif b == 0 then
      node = rshift(d[base + 3], 4) * 16777216 + d[base] * 65536 + d[base + 1] * 256 + d[base + 2]
    else
      node = band(d[base + 3], 15) * 16777216 + d[base + 4] * 65536 + d[base + 5] * 256 + d[base + 6]
    end
    i = i + 1
  end

  if node == node_count then
    return false, i
  end
  if node > node_count then
    local off = node - node_count + self.tree_size
    if off < self.data_start or off >= self.data_end then
      return nil, "search tree points outside the data section"
    end
    return off, i
  end
  return nil, "search tree ended without a record"
end

-- Projects the record at `off` through `trie` into `out[slot]`.
-- `lang` = { len = n, first = byte, buf = cdata } for the configured language.
function Reader:extract(off, trie, out, lang)
  if self.closed then
    return nil, "database is closed"
  end
  steps, bytes_left, max_string = EXTRACT_STEPS, EXTRACT_BYTES, EXTRACT_MAX_STRING
  local nxt, err = walk(self.data, off, self.data_start, self.data_end, trie, out, lang, 0)
  if not nxt then
    return nil, err
  end
  return true
end

-- Fully decodes the record at `off` (diagnostics, tests and tooling).
function Reader:record(off)
  if self.closed then
    return nil, "database is closed"
  end
  steps, bytes_left, max_string = RECORD_STEPS, RECORD_BYTES, huge
  local nxt, v = decode(self.data, off, self.data_start, self.data_end, 0)
  if not nxt then
    return nil, v
  end
  return v
end

function Reader:close()
  if self.closed then
    return
  end
  self.closed = true
  local map = self._map
  self._map, self.data = nil, nil
  if map then
    ffi_gc(map, nil)
    C.munmap(map, self.size)
  end
end

_M.Reader = Reader

return _M
