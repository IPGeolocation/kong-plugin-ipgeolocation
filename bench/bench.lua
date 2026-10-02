-- Lookup benchmarks for the plugin's MMDB reader and resolver.
--
-- usage: resty -I . bench/bench.lua <location.mmdb> <asn.mmdb> <security.mmdb> <ips-prefix>
--   <ips-prefix>.v4.txt / .v6.txt: addresses to look up (bench/sample-ips.py)
--
-- Reports CPU time per operation (os.clock) for the database work only;
-- Kong's own request processing is not included.
local mmdb = require "kong.plugins.ipgeolocation.mmdb"
local plan_mod = require "kong.plugins.ipgeolocation.plan"
local resolver = require "kong.plugins.ipgeolocation.resolver"
local iputil = require "kong.plugins.ipgeolocation.iputil"
local helpers = require "spec.ipgeolocation.helpers"

local loc_path, asn_path, sec_path, ips = arg[1], arg[2], arg[3], arg[4]
local N = tonumber(os.getenv("BENCH_N") or "") or 200000

local function rss_kib()
  for line in io.lines("/proc/self/status") do
    local v = line:match("^VmRSS:%s+(%d+)")
    if v then return tonumber(v) end
  end
end

local function load_ips(path)
  local list = {}
  for line in io.lines(path) do
    local b, n = iputil.parse(line)
    if b then list[#list + 1] = { b, n, line } end
  end
  return list
end

local v4 = load_ips(ips .. ".v4.txt")
local v6 = load_ips(ips .. ".v6.txt")
-- One address in four is random, i.e. most likely not in the database.
math.randomseed(7)
for i = 1, #v4, 4 do
  v4[i] = { { math.random(1, 223), math.random(0, 255), math.random(0, 255), math.random(0, 255) }, 4 }
end

local rss0 = rss_kib()
local loc = assert(mmdb.open(loc_path))
local asn = assert(mmdb.open(asn_path))
local sec = assert(mmdb.open(sec_path))
local readers = { [loc_path] = loc, [asn_path] = asn, [sec_path] = sec }
local function get(path) return readers[path] end
local rss_open = rss_kib()

local function bench(name, list, fn)
  local n = #list
  for i = 1, math.min(n, 2000) do fn(list[i]) end      -- warm up / JIT
  collectgarbage("collect")
  local t0 = os.clock()
  for i = 1, N do fn(list[(i - 1) % n + 1]) end
  local dt = os.clock() - t0
  print(string.format("  %-58s %8.2f us/op %11.0f ops/s", name, dt / N * 1e6, N / dt))
end

local function plan(dbs, preset, policy)
  return assert(plan_mod.compile(helpers.conf({ databases = dbs, headers = { preset = preset }, policy = policy or {} })))
end

local p_loc_min = plan({ loc_path }, "minimal")
local p_loc_std = plan({ loc_path }, "standard")
local p_loc_full = plan({ loc_path }, "full")
local p_sec = plan({ sec_path }, "none", { block_tor = true, block_vpn = true, block_proxy = true,
                                          block_known_attacker = true, block_bot = true, block_threat_score_above = 80 })
local p_multi = plan({ loc_path, asn_path, sec_path }, "standard", { block_tor = true, block_known_attacker = true,
                                                                     block_threat_score_above = 80 })

print(string.format("databases: location %.0f MiB (%d nodes), asn %.0f MiB, security %.0f MiB; N=%d",
  loc.size / 1048576, loc.node_count, asn.size / 1048576, sec.size / 1048576, N))
print(string.format("%d IPv4 / %d IPv6 addresses", #v4, #v6))

print("search tree only")
bench("IPv4 lookup (location)", v4, function(a) loc:lookup(a[1], a[2]) end)
bench("IPv6 lookup (location)", v6, function(a) loc:lookup(a[1], a[2]) end)
bench("IPv4 lookup (security)", v4, function(a) sec:lookup(a[1], a[2]) end)

print("address parsing")
bench("parse IPv4 text", v4, function(a) iputil.parse("203.0.113.77") end)
bench("parse IPv6 text", v6, function(a) iputil.parse(a[3]) end)

print("lookup + field resolution (resolver.resolve)")
bench("location, minimal preset (3 fields), IPv4", v4, function(a) resolver.resolve(p_loc_min, a[1], a[2], get) end)
bench("location, minimal preset (3 fields), IPv6", v6, function(a) resolver.resolve(p_loc_min, a[1], a[2], get) end)
bench("location, standard preset (15 fields), IPv4", v4, function(a) resolver.resolve(p_loc_std, a[1], a[2], get) end)
bench("location, full preset (all fields), IPv4", v4, function(a) resolver.resolve(p_loc_full, a[1], a[2], get) end)
bench("security policy fields only, IPv4", v4, function(a) resolver.resolve(p_sec, a[1], a[2], get) end)
bench("location + ASN + security, standard + policy, IPv4", v4, function(a) resolver.resolve(p_multi, a[1], a[2], get) end)
bench("location + ASN + security, standard + policy, IPv6", v6, function(a) resolver.resolve(p_multi, a[1], a[2], get) end)

collectgarbage("collect")
print(string.format("memory: RSS %.1f MiB before open, %.1f MiB after open, %.1f MiB after benchmarks",
  rss0 / 1024, rss_open / 1024, rss_kib() / 1024))
print(string.format("(the files total %.0f MiB; mapped pages are shared page cache, counted in RSS only once touched)",
  (loc.size + asn.size + sec.size) / 1048576))
