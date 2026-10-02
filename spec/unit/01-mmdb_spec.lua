local mmdb = require "kong.plugins.ipgeolocation.mmdb"
local iputil = require "kong.plugins.ipgeolocation.iputil"
local W = require "spec.ipgeolocation.mmdb_writer"
local fixtures = require "spec.ipgeolocation.fixtures"
local helpers = require "spec.ipgeolocation.helpers"

local function lookup(db, ip)
  local b, n = assert(iputil.parse(ip))
  return db:lookup(b, n)
end

local function get(db, ip)
  local off, plen = lookup(db, ip)
  if not off then return off, plen end
  return assert(db:record(off)), plen
end

local function write_db(dir, name, opts, nets)
  local w = W.new(opts)
  for _, n in ipairs(nets) do w:insert(n[1], n[2]) end
  return w:write(dir .. "/" .. name .. ".mmdb")
end

describe("mmdb reader", function()
  local fx, dir

  lazy_setup(function()
    fx = helpers.fixtures()
    dir = helpers.tmpdir()
  end)

  describe("opening", function()
    it("reads and validates metadata", function()
      local db = assert(mmdb.open(fx.security))
      assert.equal(6, db.ip_version)
      assert.equal(32, db.record_size)
      assert.equal("ipgeolocation.io IP-Security Database", db.metadata.database_type)
      assert.equal(1790000000, db.metadata.build_epoch)
      assert.equal(2, db.metadata.binary_format_major_version)
      db:close()
    end)

    for _, rs in ipairs({ 24, 28, 32 }) do
      it("resolves the same records with " .. rs .. "-bit search tree records", function()
        local path = fixtures.build("location", dir .. "/loc-" .. rs .. ".mmdb", { record_size = rs })
        local db = assert(mmdb.open(path))
        assert.equal(rs, db.record_size)
        local rec, plen = get(db, "203.0.113.77")
        assert.equal("Lahore", rec.location.city.name.en)
        assert.equal(24, plen)
        assert.equal("Tokyo", (get(db, "2001:db8:1:ffff::1")).location.city.name.en)
        assert.equal("San Francisco", (get(db, "192.0.2.200")).location.city.name.en)
        assert.equal("Mountain View", (get(db, "192.0.2.10")).location.city.name.en)
        db:close()
      end)
    end

    it("rejects missing files, directories and non-MMDB content", function()
      assert.is_nil((mmdb.open(dir .. "/does-not-exist.mmdb")))
      local _, err = mmdb.open(dir)
      assert.is_string(err)
      W.write_bytes(dir .. "/empty.mmdb", "")
      _, err = mmdb.open(dir .. "/empty.mmdb")
      assert.matches("too small", err)
      W.write_bytes(dir .. "/random.mmdb", string.rep("not an mmdb database ", 200))
      _, err = mmdb.open(dir .. "/random.mmdb")
      assert.matches("metadata section not found", err)
      assert.is_nil((mmdb.open("")))
      assert.is_nil((mmdb.open(nil)))
    end)

    it("rejects truncated files", function()
      local bytes = W.read_bytes(fx.location)
      for _, cut in ipairs({ 100, math.floor(#bytes / 2), #bytes - 20 }) do
        local p = W.write_bytes(dir .. "/trunc-" .. cut .. ".mmdb", bytes:sub(1, cut))
        assert.is_nil((mmdb.open(p)), "cut " .. cut)
      end
    end)

    it("rejects invalid metadata values", function()
      local function md(over)
        local m = {
          node_count = W.uint32(1), record_size = W.uint16(32), ip_version = W.uint16(6),
          database_type = "x", languages = W.array({}), binary_format_major_version = W.uint16(2),
          binary_format_minor_version = W.uint16(0), build_epoch = W.uint64(1), description = {},
        }
        for k, v in pairs(over) do m[k] = v end
        return m
      end
      local cases = {
        { { record_size = W.uint16(20) }, "unsupported record_size" },
        { { ip_version = W.uint16(5) }, "invalid ip_version" },
        { { binary_format_major_version = W.uint16(3) }, "unsupported binary format" },
        { { node_count = W.uint32(4000000000) }, "search tree is larger than the file" },
        { { node_count = "many" }, "invalid node_count" },
      }
      for i, c in ipairs(cases) do
        local w = W.new({ metadata = md(c[1]) })
        w:insert("203.0.113.0/24", { a = "b" })
        local _, err = mmdb.open(w:write(dir .. "/md-" .. i .. ".mmdb"))
        assert.matches(c[2], err)
      end
    end)

    it("detects a corrupt search tree through the data section separator", function()
      local bytes = W.read_bytes(fx.asn)
      local db = assert(mmdb.open(fx.asn))
      local tree_size = db.tree_size
      db:close()
      local corrupt = bytes:sub(1, tree_size + 3) .. "\255" .. bytes:sub(tree_size + 5)
      local _, err = mmdb.open(W.write_bytes(dir .. "/sep.mmdb", corrupt))
      assert.matches("separator", err)
    end)
  end)

  describe("lookups", function()
    it("distinguishes a record, no record and an IPv6 lookup in an IPv4 tree", function()
      local db = assert(mmdb.open(fx.security))
      local off, plen = lookup(db, "203.0.113.10")
      assert.is_number(off)
      assert.equal(32, plen)
      off, plen = lookup(db, "203.0.113.200")
      assert.is_false(off)
      assert.is_number(plen)
      db:close()

      local p = write_db(dir, "v4only", { ip_version = 4 }, { { "203.0.113.0/24", { x = "y" } } })
      db = assert(mmdb.open(p))
      assert.equal("y", (get(db, "203.0.113.9")).x)
      local r, err = lookup(db, "2001:db8::1")
      assert.is_nil(r)
      assert.equal(mmdb.ERR_IPV6_IN_IPV4, err)
      db:close()
    end)

    it("finds IPv4 data through IPv4-mapped aliases only when the database has them", function()
      local loc = assert(mmdb.open(fx.location))
      local b = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 203, 0, 113, 5 }
      local off = loc:lookup(b, 16)
      assert.is_number(off)
      local sec = assert(mmdb.open(fx.security))
      b[16] = 10
      assert.is_false((sec:lookup(b, 16)))
      -- which is why the plugin normalises ::ffff:a.b.c.d to IPv4 first
      local v4, n = iputil.parse("::ffff:203.0.113.10")
      assert.equal(4, n)
      assert.is_number((sec:lookup(v4, n)))
      loc:close()
      sec:close()
    end)

    it("refuses to work on a closed database", function()
      local db = assert(mmdb.open(fx.asn))
      db:close()
      db:close()
      local r, err = lookup(db, "203.0.113.1")
      assert.is_nil(r)
      assert.matches("closed", err)
      assert.is_nil((db:record(100)))
    end)
  end)

  describe("decoding", function()
    it("decodes every MMDB data type", function()
      local p = write_db(dir, "types", {}, { { "203.0.113.0/24", {
        utf8 = "unicode ☯ ✓", u16 = W.uint16(65535), u32 = W.uint32(4294967295),
        u64 = W.uint64(2^60), u128 = W.uint128(2^100), i32 = W.int32(-268435456), i32p = W.int32(42),
        dbl = W.double(-122.08385), flt = W.float(1.5), bin = W.bytes("\0\1\2*"), yes = true, no = false,
        list = W.array({ 1, "two", W.array({ 3 }) }), empty_list = W.array({}), empty_map = {},
        nested = { a = { b = { c = "deep" } } }, zero = W.uint32(0),
      } } })
      local db = assert(mmdb.open(p))
      local r = assert(get(db, "203.0.113.1"))
      assert.equal("unicode ☯ ✓", r.utf8)
      assert.equal(65535, r.u16)
      assert.equal(4294967295, r.u32)
      assert.equal(2^60, r.u64)
      assert.equal(2^100, r.u128)
      assert.equal(-268435456, r.i32)
      assert.equal(42, r.i32p)
      assert.equal(-122.08385, r.dbl)
      assert.equal(1.5, r.flt)
      assert.equal("\0\1\2*", r.bin)
      assert.is_true(r.yes)
      assert.is_false(r.no)
      assert.same({ 1, "two", { 3 } }, r.list)
      assert.equal(mmdb.array_mt, getmetatable(r.list))
      assert.equal(mmdb.array_mt, getmetatable(r.empty_list))
      assert.is_nil(getmetatable(r.empty_map))
      assert.equal("deep", r.nested.a.b.c)
      assert.equal(0, r.zero)
      db:close()
    end)

    it("follows pointers for deduplicated keys and strings", function()
      local db = assert(mmdb.open(fx.location))
      for _, ip in ipairs({ "198.51.100.1", "2001:db8:2::1", "203.0.113.1" }) do
        local r = assert(get(db, ip))
        assert.is_string(r.location.country.continent.name.en)
      end
      db:close()
    end)

    local function crafted(name, value)
      local db = assert(mmdb.open(write_db(dir, name, { dedupe = false }, { { "203.0.113.0/24", value } })))
      local off = assert(lookup(db, "203.0.113.1"))
      return db, off
    end

    it("rejects pointers outside the data section", function()
      local db, off = crafted("badptr", { x = W.pointer(100000000) })
      local r, err = db:record(off)
      assert.is_nil(r)
      assert.matches("pointer outside data section", err)
      db:close()
    end)

    it("rejects pointers to pointers", function()
      -- Layout: map ctrl (1 byte), key "a" (2 bytes), then the value at
      -- offset 3: a pointer to offset 3, i.e. to itself, a pointer.
      local db, off = crafted("ptrptr", { a = W.pointer(3) })
      local r, err = db:record(off)
      assert.is_nil(r)
      assert.matches("pointer to pointer", err)
      db:close()
    end)

    it("terminates on pointer cycles", function()
      -- The record map is at offset 0; its value points back at the map.
      local db, off = crafted("cycle", { a = W.pointer(0) })
      local r, err = db:record(off)
      assert.is_nil(r)
      assert.matches("nested too deeply", err)
      db:close()
    end)

    it("rejects values that run past the end of the data section", function()
      local db, off = crafted("overrun", { x = W.raw(W.ctrl(2, 60000) .. "abc") })
      local r, err = db:record(off)
      assert.is_nil(r)
      assert.is_string(err)
      db:close()
    end)

    it("bounds nesting depth", function()
      local v = "bottom"
      for _ = 1, 40 do v = { k = v } end
      local db, off = crafted("deep", v)
      local r, err = db:record(off)
      assert.is_nil(r)
      assert.matches("nested too deeply", err)
      db:close()
    end)

    it("bounds the work spent on a single record during extraction", function()
      local big = {}
      for i = 1, 30000 do big[i] = i end
      local db, off = crafted("huge", { big = W.array(big), is_tor = "true" })
      local trie = { n = 0, keys = {}, lens = {}, first = {}, bufs = {}, kids = {} }
      local ffi = require "ffi"
      local function add(node, key)
        node.n = node.n + 1
        local buf = ffi.new("uint8_t[?]", #key); ffi.copy(buf, key, #key)
        node.keys[node.n], node.lens[node.n], node.first[node.n], node.bufs[node.n] = key, #key, key:byte(1), buf
        local child = { n = 0, keys = {}, lens = {}, first = {}, bufs = {}, kids = {}, slots = { node.n } }
        node.kids[node.n] = child
      end
      add(trie, "is_tor")
      local lang = { len = 2, first = 101, buf = ffi.new("uint8_t[2]", { 101, 110 }) }
      local ok, err = db:extract(off, trie, {}, lang)
      assert.is_nil(ok)
      assert.matches("budget", err)
      db:close()
    end)

    it("handles record offsets beyond 2^31 (multi-GiB databases)", function()
      if os.getenv("IPGEO_SKIP_LARGE") then
        pending("IPGEO_SKIP_LARGE is set")
        return
      end
      local pad = 2^31 + 123456789
      local path = dir .. "/large-sparse.mmdb"
      local ok = pcall(fixtures.build, "security", path, { data_padding = pad })
      if not ok then
        pending("cannot create a sparse file here")
        return
      end
      local db = assert(mmdb.open(path))
      assert.is_true(db.size > 2^31)
      local off = assert(lookup(db, "203.0.113.10"))
      assert.is_true(off > 2^31)
      local r = assert(db:record(off))
      assert.equal("true", r.is_tor)
      assert.equal(90, r.threat_score)
      db:close()
      os.remove(path)
    end)
  end)
end)
