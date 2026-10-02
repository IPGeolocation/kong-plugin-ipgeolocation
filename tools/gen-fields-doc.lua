-- Prints the field reference (docs/FIELDS.md) from the field catalog, so the
-- documentation cannot drift from the code.
--   resty -I . tools/gen-fields-doc.lua > docs/FIELDS.md
local fields = require "kong.plugins.ipgeolocation.fields"

local in_preset = {}
for name, list in pairs(fields.presets) do
  for _, f in ipairs(list) do
    in_preset[f] = in_preset[f] or {}
    in_preset[f][name] = true
  end
end

local function presets(f)
  local p = in_preset[f] or {}
  if p.minimal then return "minimal" end
  if p.standard then return "standard" end
  if p.full then return "full" end
  return "custom only"
end

local KIND = { string = "text", number = "number", bool = "boolean", asn = "ASN", list = "list" }
local TITLES = {
  location = "Location",
  network = "Company, ISP and ASN",
  security = "Security and threat intelligence",
  abuse = "Abuse contact",
}

print("# Field reference")
print()
print("Generated from `kong/plugins/ipgeolocation/fields.lua` by `tools/gen-fields-doc.lua`.")
print()
print("Each field can be sent upstream as a header (through a preset or `headers.custom`) and is")
print("available to other plugins in `kong.ctx.shared.ipgeolocation.fields`. Database paths are")
print("tried in order inside each database; across databases the first non-empty value wins.")
print("`{lang}` is the configured `headers.language`, falling back to `en`.")
print()
print("\"Smallest preset\" is the smallest preset that includes the field (`minimal` is contained")
print("in `standard`, which is contained in `full`). \"custom only\" fields must be mapped explicitly.")
print()
local current
for _, f in ipairs(fields.list) do
  if f.category ~= current then
    current = f.category
    print()
    print("## " .. (TITLES[current] or current))
    print()
    print("| Field | Header | Type | Smallest preset | Database paths |")
    print("|---|---|---|---|---|")
  end
  local paths = {}
  for _, p in ipairs(f.paths) do paths[#paths + 1] = "`" .. p .. "`" end
  if f.presence then
    for _, p in ipairs(f.presence) do paths[#paths + 1] = "presence of `" .. p .. "`" end
  end
  print(string.format("| `%s` | `%s` | %s | %s | %s |", f.name, fields.header_name(f.name), KIND[f.kind] or f.kind,
                      presets(f.name), table.concat(paths, ", ")))
end
print()
print("## Request metadata")
print()
print("| Field | Header | Type | Smallest preset | Source |")
print("|---|---|---|---|---|")
print("| `ip` | `X-IPGeo-IP` | text | full | the client address Kong determined (`kong.client.get_forwarded_ip()`), IPv4-mapped IPv6 normalised to IPv4 |")
print()
print("## Presets")
print()
for _, name in ipairs({ "minimal", "standard", "full" }) do
  local list = {}
  for _, f in ipairs(fields.presets[name]) do list[#list + 1] = "`" .. f .. "`" end
  print("- **" .. name .. "** (" .. #fields.presets[name] .. "): " .. table.concat(list, ", "))
end
print()
print("`full` excludes unbounded lists (`asn_routes`, `asn_peers`, `asn_upstreams`, `asn_downstreams`), which can")
print("hold thousands of entries; map them with `headers.custom` if you need them (values are truncated to")
print("`headers.max_value_length`).")
