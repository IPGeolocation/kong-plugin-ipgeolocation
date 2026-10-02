-- Compiles a plugin configuration into an execution plan, once per
-- configuration table (Kong builds new tables whenever configuration
-- changes, so a weak-keyed cache is enough):
--
--   * the set of fields to resolve: every header field plus every field the
--     policy needs, and nothing else;
--   * a trie of all their candidate key paths, walked once per record;
--   * the header map, the managed header names and formatting options;
--   * the compiled policy and exemptions.

local ffi = require "ffi"
local fields = require "kong.plugins.ipgeolocation.fields"
local policy = require "kong.plugins.ipgeolocation.policy"
local iputil = require "kong.plugins.ipgeolocation.iputil"

local ipairs, pairs, type, setmetatable = ipairs, pairs, type, setmetatable
local lower, gsub, byte = string.lower, string.gsub, string.byte
local sort = table.sort

local _M = {}

local cache = setmetatable({}, { __mode = "k" })

local function new_node()
  return { n = 0, keys = {}, lens = {}, first = {}, bufs = {}, kids = {}, slots = nil }
end

local function key_buffer(key)
  local buf = ffi.new("uint8_t[?]", #key)
  ffi.copy(buf, key, #key)
  return buf
end

local function add_path(root, path, slot)
  local node = root
  for key in path:gmatch("[^%.]+") do
    local idx
    for i = 1, node.n do
      if node.keys[i] == key then
        idx = i
        break
      end
    end
    if not idx then
      idx = node.n + 1
      node.n = idx
      node.keys[idx] = key
      node.lens[idx] = #key
      node.first[idx] = byte(key, 1)
      node.bufs[idx] = key_buffer(key)
      node.kids[idx] = new_node()
    end
    node = node.kids[idx]
  end
  local slots = node.slots
  if not slots then
    slots = {}
    node.slots = slots
  end
  slots[#slots + 1] = slot
end

local function language_info(code)
  return { code = code, len = #code, first = byte(code, 1), buf = key_buffer(code) }
end

-- Lower-cases and folds underscores into dashes: many backends (CGI, WSGI,
-- PHP) treat "X_IPGeo_Country_Code" as "X-IPGeo-Country-Code", and Kong passes
-- underscores in header names through.
local function fold(name)
  return (gsub(lower(name), "_", "-"))
end
_M.fold = fold

-- Kong represents unset optional fields as ngx.null (a truthy userdata) in
-- some code paths; every option is type-checked so null means "unset".
local function opt(value, kind, default)
  if type(value) == kind then
    return value
  end
  return default
end
_M.opt = opt

local function compile(conf)
  local hconf = opt(conf.headers, "table", {})
  local pconf = opt(conf.policy, "table", {})

  -- Header map: preset first, then explicit entries ("" removes a header).
  local preset = fields.presets[opt(hconf.preset, "string", "minimal")] or fields.presets.minimal
  local map = {}
  for _, field in ipairs(preset) do
    local name = fields.header_name(field)
    map[fold(name)] = { name = name, field = field }
  end
  local managed = {}
  if type(hconf.custom) == "table" then
    for name, field in pairs(hconf.custom) do
      local key = fold(name)
      managed[key] = true
      if type(field) ~= "string" or field == "" then
        map[key] = nil
      else
        map[key] = { name = name, field = field }
      end
    end
  end
  local header_list = {}
  for _, h in pairs(map) do
    header_list[#header_list + 1] = h
  end
  sort(header_list, function(a, b) return a.name < b.name end)

  local compiled_policy = policy.compile(pconf)

  -- Fields to resolve.
  local wanted, order = {}, {}
  local function want(name)
    if name ~= fields.IP_FIELD and not wanted[name] and fields.by_name[name] then
      wanted[name] = true
      order[#order + 1] = name
    end
  end
  for _, h in ipairs(header_list) do want(h.field) end
  for _, name in ipairs(compiled_policy.required) do want(name) end

  local trie = new_node()
  local slot = 0
  local plan_fields = {}
  for _, name in ipairs(order) do
    local def = fields.by_name[name]
    local pf = { name = name, kind = def.kind, slots = {} }
    for _, path in ipairs(def.paths) do
      slot = slot + 1
      add_path(trie, path, slot)
      pf.slots[#pf.slots + 1] = slot
    end
    if def.presence then
      pf.presence_slots = {}
      for _, path in ipairs(def.presence) do
        slot = slot + 1
        add_path(trie, path, slot)
        pf.presence_slots[#pf.presence_slots + 1] = slot
      end
    end
    plan_fields[#plan_fields + 1] = pf
  end

  local exempt
  if type(pconf.exempt_ips) == "table" and #pconf.exempt_ips > 0 then
    exempt = {}
    for _, cidr in ipairs(pconf.exempt_ips) do
      local c, err = iputil.parse_cidr(cidr)
      if not c then
        return nil, "invalid exempt_ips entry '" .. tostring(cidr) .. "': " .. err
      end
      exempt[#exempt + 1] = c
    end
  end

  local one_zero = hconf.boolean_format == "one_zero"
  local language = opt(hconf.language, "string", "en")
  if language == "" then
    language = "en"
  end

  return {
    plugin_id = conf.__plugin_id,
    databases = opt(conf.databases, "table", {}),
    fields = plan_fields,
    trie = trie,
    lang = language_info(language),
    headers = header_list,
    managed = managed,
    true_value = one_zero and "1" or "true",
    false_value = one_zero and "0" or "false",
    list_separator = opt(hconf.list_separator, "string", ","),
    max_len = opt(hconf.max_value_length, "number", 1024),
    policy = compiled_policy,
    exempt = exempt,
    allow_private = pconf.allow_private ~= false,
    fail_open = pconf.fail_open ~= false,
    dry_run = pconf.dry_run == true,
    status = opt(pconf.status_code, "number", 403),
    message = opt(pconf.message, "string", "Access denied"),
    log_serialize = conf.log_serialize == true,
  }
end

_M.compile = compile

function _M.get(conf)
  local plan = cache[conf]
  if plan then
    return plan
  end
  local err
  plan, err = compile(conf)
  if not plan then
    return nil, err
  end
  cache[conf] = plan
  return plan
end

return _M
