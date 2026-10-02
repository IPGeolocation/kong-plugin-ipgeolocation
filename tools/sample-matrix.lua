-- Resolves every catalog field against addresses from real databases and
-- prints which fields each database provides (docs/DATABASES.md section).
--   python3 tools/sample-hits.py /path/to/samples > /tmp/hits.json
--   resty -I . tools/sample-matrix.lua /tmp/hits.json
local cjson = require "cjson.safe"
local mmdb = require "kong.plugins.ipgeolocation.mmdb"
local plan_mod = require "kong.plugins.ipgeolocation.plan"
local resolver = require "kong.plugins.ipgeolocation.resolver"
local iputil = require "kong.plugins.ipgeolocation.iputil"
local fields = require "kong.plugins.ipgeolocation.fields"

local f = assert(io.open(arg[1]))
local hits = assert(cjson.decode(f:read("*a")))
f:close()

local custom = {}
for _, def in ipairs(fields.list) do custom["X-F-" .. def.name] = def.name end

local paths = {}
for p in pairs(hits) do paths[#paths + 1] = p end
table.sort(paths)

for _, path in ipairs(paths) do
  local reader = assert(mmdb.open(path))
  local plan = assert(plan_mod.compile({ databases = { path }, headers = { preset = "none", custom = custom } }))
  local seen, n, found = {}, 0, 0
  for _, ip in ipairs(hits[path]) do
    local b, len = iputil.parse(ip)
    if b then
      local values, _, ok = resolver.resolve(plan, b, len, function() return reader end)
      if ok then found = found + 1 end
      for name in pairs(values) do
        if not seen[name] then seen[name] = true; n = n + 1 end
      end
    end
  end
  local list = {}
  for _, def in ipairs(fields.list) do
    if seen[def.name] then list[#list + 1] = "`" .. def.name .. "`" end
  end
  local md = reader.metadata
  local dir = path:match("([^/]+)/[^/]+$") or ""
  print(string.format("| `%s` (%s) | %d | %s | %d/%d | %s |", path:match("[^/]+$"), dir:gsub("%-sample$", ""),
    md.ip_version, os.date("!%Y-%m-%d", md.build_epoch), found, #hits[path], #list > 0 and table.concat(list, ", ") or "none"))
  reader:close()
end
