local registry = require "kong.plugins.ipgeolocation.registry"
local fixtures = require "spec.ipgeolocation.fixtures"
local helpers = require "spec.ipgeolocation.helpers"
local kong_mock = require "spec.ipgeolocation.kong_mock"
local W = require "spec.ipgeolocation.mmdb_writer"
local iputil = require "kong.plugins.ipgeolocation.iputil"

local function country(reader, ip)
  local b, n = iputil.parse(ip)
  local off = assert(reader:lookup(b, n))
  return reader:record(off).location.country.code2
end

local function write_country(path, code)
  local w = W.new()
  w:insert("203.0.113.0/24", { location = { country = { code2 = code } } })
  return w:write(path)
end

-- Replace atomically, as an updater should: write a temporary file, rename.
local function replace(path, code)
  write_country(path .. ".tmp", code)
  assert(os.rename(path .. ".tmp", path))
end

describe("registry", function()
  local dir, req, clock

  before_each(function()
    dir = helpers.tmpdir()
    req = kong_mock.install()
    clock = 1000
    registry.now = function() return clock end
  end)

  after_each(function()
    registry.reset()
    kong_mock.uninstall()
  end)

  it("loads configured databases and shares one reader per file", function()
    local fx = helpers.fixtures()
    registry.sync({ { databases = { fx.location, fx.asn } }, { databases = { fx.location } } })
    local a = assert(registry.get(fx.location))
    local b = assert(registry.get(fx.location))
    assert.equal(a, b)
    assert.is_truthy(registry.get(fx.asn))
    assert.equal(1, #kong_mock.logged(req, "notice", "loaded " .. fx.location))
  end)

  it("unloads databases that are no longer configured", function()
    local fx = helpers.fixtures()
    registry.sync({ { databases = { fx.location, fx.asn } } })
    local asn = assert(registry.get(fx.asn))
    registry.sync({ { databases = { fx.location } } })
    assert.is_true(asn.closed)
    registry.sync(nil)
    assert.same({}, registry.status())
  end)

  it("retries a missing database until it appears", function()
    local path = dir .. "/later.mmdb"
    registry.sync({ { databases = { path } } })
    local r, err = registry.get(path)
    assert.is_nil(r)
    assert.matches("cannot stat", err)
    assert.equal(1, #kong_mock.logged(req, "err", "unavailable"))
    write_country(path, "PK")
    clock = clock + registry.RETRY - 1
    registry.tick()
    assert.is_nil((registry.get(path)))
    clock = clock + 2
    registry.tick()
    assert.equal("PK", country(assert(registry.get(path)), "203.0.113.1"))
  end)

  it("retries a database the operating system refused, although the file did not change", function()
    local path = write_country(dir .. "/denied.mmdb", "PK")
    local real = registry.open
    local opened = 0
    -- chmod and chown change neither size nor mtime, so the signature stays the same
    registry.open = function(p)
      opened = opened + 1
      if opened == 1 then
        return nil, "cannot open file: Permission denied", true
      end
      return real(p)
    end
    registry.sync({ { databases = { path } } })
    local r, err = registry.get(path)
    assert.is_nil(r)
    assert.matches("Permission denied", err)
    clock = clock + registry.RETRY + 1
    registry.tick()
    registry.open = real
    assert.equal(2, opened)
    assert.equal("PK", country(assert(registry.get(path)), "203.0.113.1"))
  end)

  it("does not re-open an unchanged file whose content was rejected", function()
    local path = W.write_bytes(dir .. "/broken.mmdb", string.rep("not an mmdb database ", 200))
    local real = registry.open
    local opened = 0
    registry.open = function(p) opened = opened + 1 return real(p) end
    registry.sync({ { databases = { path } } })
    clock = clock + registry.RETRY + 1
    registry.tick()
    registry.open = real
    assert.equal(1, opened)
    assert.matches("metadata section not found", select(2, registry.get(path)))
  end)

  it("never opens a database on the request path once configured", function()
    local fx = helpers.fixtures()
    registry.sync({ { databases = { fx.asn } } })
    local opened = 0
    local real = registry.open
    registry.open = function(...) opened = opened + 1 return real(...) end
    for _ = 1, 10 do assert(registry.get(fx.asn)) end
    registry.open = real
    assert.equal(0, opened)
  end)

  it("does not check for updates when refresh is disabled", function()
    local path = write_country(dir .. "/static.mmdb", "PK")
    registry.sync({ { databases = { path }, database_refresh_interval = 0 } })
    local first = assert(registry.get(path))
    replace(path, "DE")
    clock = clock + 100000
    registry.tick()
    assert.equal(first, registry.get(path))
    assert.equal("PK", country(first, "203.0.113.1"))
  end)

  it("swaps in an updated database after validating it", function()
    local path = write_country(dir .. "/live.mmdb", "PK")
    registry.sync({ { databases = { path }, database_refresh_interval = 60 } })
    local first = assert(registry.get(path))
    replace(path, "DE")
    clock = clock + 59
    registry.tick()
    assert.equal(first, registry.get(path))
    clock = clock + 2
    registry.tick()
    local second = assert(registry.get(path))
    assert.are_not.equal(first, second)
    assert.is_true(first.closed)
    assert.equal("DE", country(second, "203.0.113.1"))
    assert.equal(1, #kong_mock.logged(req, "notice", "reloaded"))
  end)

  it("keeps the database in service when the replacement is invalid", function()
    local path = write_country(dir .. "/keep.mmdb", "PK")
    registry.sync({ { databases = { path }, database_refresh_interval = 60 } })
    local first = assert(registry.get(path))
    W.write_bytes(path .. ".tmp", "garbage that is not an MMDB file")
    assert(os.rename(path .. ".tmp", path))
    clock = clock + 61
    registry.tick()
    assert.equal(first, registry.get(path))
    assert.is_false(first.closed)
    assert.equal("PK", country(first, "203.0.113.1"))
    assert.equal(1, #kong_mock.logged(req, "err", "keeping the database already in service"))
    -- the same broken file is not re-opened on every tick
    clock = clock + 61
    registry.tick()
    assert.equal(1, #kong_mock.logged(req, "err", "keeping the database already in service"))
    -- a good file is picked up again
    replace(path, "JP")
    clock = clock + 61
    registry.tick()
    assert.equal("JP", country(assert(registry.get(path)), "203.0.113.1"))
  end)

  it("warns when a database is modified in place instead of replaced", function()
    local path = write_country(dir .. "/inplace.mmdb", "PK")
    registry.sync({ { databases = { path }, database_refresh_interval = 60 } })
    assert(registry.get(path))
    local real = registry.stat
    registry.stat = function(p)
      local a = real(p)
      if a then a.modification = a.modification + 3600 end   -- same inode, new mtime
      return a
    end
    clock = clock + 61
    registry.tick()
    registry.stat = real
    assert.equal(1, #kong_mock.logged(req, "warn", "modified in place"))
  end)

  it("uses the shortest refresh interval requested for a file, at least 60 seconds", function()
    local path = write_country(dir .. "/multi.mmdb", "PK")
    registry.sync({
      { databases = { path }, database_refresh_interval = 0 },
      { databases = { path }, database_refresh_interval = 600 },
      { databases = { path }, database_refresh_interval = 120 },
    })
    assert.equal(120, registry.status()[path].refresh)
    registry.sync({ { databases = { path }, database_refresh_interval = 5 } })
    assert.equal(registry.MIN_REFRESH, registry.status()[path].refresh)
  end)

  it("rejects paths that are not regular files", function()
    registry.sync({ { databases = { dir } } })
    local r, err = registry.get(dir)
    assert.is_nil(r)
    assert.matches("not a regular file", err)
  end)

  it("opens lazily if a request arrives before configure ran", function()
    local fx = helpers.fixtures()
    assert(registry.get(fx.company))
  end)

  it("builds fixtures used across suites", function()
    assert.is_string(fixtures.build("asn", dir .. "/a.mmdb"))
  end)
end)
