-- Per-worker database registry.
--
-- * Databases are opened from the plugin's `configure` handler, which Kong
--   runs in every worker whenever the plugin iterator is rebuilt. Normal
--   requests never open files. (A lazy open on first use remains as a
--   fallback if a request ever arrives before `configure` ran.)
-- * One reader per file per worker is shared by every plugin instance that
--   references the file. The kernel shares the mapped pages across workers.
-- * A database that is missing or invalid is retried every RETRY seconds
--   without blocking traffic, so a Kong that starts before its databases
--   have been downloaded recovers on its own.
-- * With `database_refresh_interval` > 0 the file is checked with stat(2)
--   at that interval. A changed file is opened and fully validated before it
--   replaces the current one; if validation fails the current database stays
--   in service. Workers swap independently, so for up to one interval
--   different workers may serve different releases.

local mmdb = require "kong.plugins.ipgeolocation.mmdb"

local pairs, ipairs, pcall, tostring, type = pairs, ipairs, pcall, tostring, type
local floor = math.floor
local format = string.format

local has_lfs, lfs = pcall(require, "lfs")

local _M = {
  TICK = 10,
  RETRY = 30,
  MIN_REFRESH = 60,
}

local entries = {}
local timer_started = false

-- Seams for tests.
_M.open = mmdb.open
function _M.now()
  return ngx.now()
end
function _M.stat(path)
  if not has_lfs then
    return nil, "LuaFileSystem (lfs) is not available"
  end
  return lfs.attributes(path)
end

local function log(level, ...)
  local k = kong
  if k and k.log and k.log[level] then
    return k.log[level](...)
  end
  ngx.log(ngx[level:upper()] or ngx.NOTICE, ...)
end

local function signature(attr)
  return tostring(attr.dev) .. ":" .. tostring(attr.ino) .. ":" .. tostring(attr.size) .. ":"
         .. tostring(attr.modification)
end

local function describe(reader)
  local md = reader.metadata or {}
  local built = md.build_epoch and os.date("!%Y-%m-%d %H:%M:%SZ", md.build_epoch) or "unknown"
  return format("%s, built %s, %.1f MiB, %d nodes", md.database_type ~= "" and md.database_type or "MMDB",
                built, reader.size / 1048576, md.node_count or 0)
end

local function set_error(e, err)
  if e.err ~= err then
    e.err = err
    if e.reader then
      log("err", "[ipgeolocation] could not reload ", e.path, " (", err,
          "); keeping the database already in service")
    else
      log("err", "[ipgeolocation] database ", e.path, " is unavailable: ", err)
    end
  end
end

-- Opens the file and, on success, swaps it in. Never closes the current
-- reader unless the replacement validated.
local function load(e)
  local attr, err = _M.stat(e.path)
  if not attr then
    set_error(e, "cannot stat file: " .. tostring(err))
    return false
  end
  if attr.mode ~= "file" then
    set_error(e, "not a regular file")
    return false
  end
  local sig = signature(attr)
  if sig == e.failed_sig then
    return false      -- unchanged since the last failed attempt
  end
  local reader, oerr, os_error = _M.open(e.path)
  if not reader then
    -- Only content is tied to the signature. An operating system error such
    -- as "Permission denied" is fixed without changing size or mtime
    -- (chmod, chown), so it is retried on the normal schedule.
    e.failed_sig = not os_error and sig or nil
    set_error(e, oerr)
    return false
  end
  local old = e.reader
  e.reader, e.sig, e.attr = reader, sig, attr
  e.err, e.failed_sig = nil, nil
  e.loaded_at = _M.now()
  if old then
    old:close()
    log("notice", "[ipgeolocation] reloaded ", e.path, " (", describe(reader), ")")
  else
    log("notice", "[ipgeolocation] loaded ", e.path, " (", describe(reader), ")")
  end
  return true
end

local function schedule(e, now)
  if not e.reader then
    e.next_check = now + _M.RETRY
  elseif e.refresh and e.refresh > 0 then
    e.next_check = now + e.refresh
  else
    e.next_check = nil
  end
end

local function check_for_update(e)
  local attr = _M.stat(e.path)
  if not attr or attr.mode ~= "file" then
    return    -- vanished or replaced by something else: keep serving the mapped copy
  end
  local sig = signature(attr)
  if sig == e.sig or sig == e.failed_sig then
    return
  end
  if e.attr and attr.ino == e.attr.ino and attr.dev == e.attr.dev then
    log("warn", "[ipgeolocation] ", e.path, " was modified in place. Replace database files ",
        "atomically (write a temporary file in the same directory, then rename it over the old one); ",
        "rewriting a mapped file can serve torn data or crash workers")
  end
  load(e)
end

function _M.tick()
  local now = _M.now()
  for _, e in pairs(entries) do
    if e.next_check and now >= e.next_check then
      if not e.reader then
        load(e)
      else
        check_for_update(e)
      end
      schedule(e, now)
    end
  end
end

local function ensure_timer()
  if timer_started then
    return
  end
  local needed = false
  for _, e in pairs(entries) do
    if e.next_check then
      needed = true
      break
    end
  end
  if not needed or not (ngx and ngx.timer and ngx.timer.every) then
    return
  end
  local ok, err = ngx.timer.every(_M.TICK, function(premature)
    if premature then
      return
    end
    local pok, perr = pcall(_M.tick)
    if not pok then
      log("err", "[ipgeolocation] database refresh failed: ", perr)
    end
  end)
  if ok then
    timer_started = true
  else
    log("err", "[ipgeolocation] could not start the database refresh timer: ", err)
  end
end

local function normalize_interval(v)
  v = type(v) == "number" and v or 0
  if v <= 0 then
    return 0
  end
  v = floor(v)
  if v < _M.MIN_REFRESH then
    v = _M.MIN_REFRESH
  end
  return v
end

-- Called from the plugin's `configure` handler with every active
-- configuration of this plugin (or nil when there is none).
function _M.sync(configs)
  local wanted = {}
  if type(configs) == "table" then
    for _, conf in ipairs(configs) do
      local interval = normalize_interval(conf.database_refresh_interval)
      if type(conf.databases) == "table" then
        for _, path in ipairs(conf.databases) do
          if type(path) == "string" then
            -- the shortest non-zero interval requested for a file wins
            local cur = wanted[path]
            if cur == nil or (interval > 0 and (cur == 0 or interval < cur)) then
              wanted[path] = interval
            end
          end
        end
      end
    end
  end

  for path, e in pairs(entries) do
    if wanted[path] == nil then
      if e.reader then
        e.reader:close()
      end
      entries[path] = nil
      log("notice", "[ipgeolocation] unloaded ", path, " (no longer configured)")
    end
  end

  local now = _M.now()
  for path, interval in pairs(wanted) do
    local e = entries[path]
    if not e then
      e = { path = path, refresh = interval }
      entries[path] = e
      load(e)
      schedule(e, now)
    else
      if not e.reader then
        load(e)
      end
      if e.refresh ~= interval or (e.next_check == nil and (not e.reader or interval > 0)) then
        e.refresh = interval
        schedule(e, now)
      end
    end
  end

  ensure_timer()
end

-- Returns the reader for `path`, or nil and the reason it is unavailable.
function _M.get(path)
  local e = entries[path]
  if not e then
    e = { path = path, refresh = 0 }
    entries[path] = e
    load(e)
    schedule(e, _M.now())
    ensure_timer()
  end
  local reader = e.reader
  if reader then
    return reader
  end
  return nil, e.err or "database not loaded"
end

function _M.status()
  local out = {}
  for path, e in pairs(entries) do
    out[path] = {
      loaded = e.reader ~= nil,
      error = e.err,
      refresh = e.refresh,
      next_check = e.next_check,
      metadata = e.reader and e.reader.metadata or nil,
    }
  end
  return out
end

-- Test helper: drops every entry.
function _M.reset()
  for path, e in pairs(entries) do
    if e.reader then
      e.reader:close()
    end
    entries[path] = nil
  end
  timer_started = false
end

return _M
