-- Validates MMDB files with the plugin's own reader (used by the updater's
-- IPGEO_VALIDATE hook). Exits non-zero when a file does not open.
--   resty -I <repository> tools/mmdb-check.lua <file.mmdb> [...]
local mmdb = require "kong.plugins.ipgeolocation.mmdb"

local status = 0
for i = 1, #arg do
  local reader, err = mmdb.open(arg[i])
  if not reader then
    io.stderr:write(arg[i], ": invalid: ", tostring(err), "\n")
    status = 1
  else
    local md = reader.metadata
    print(string.format("%s: %s, IPv%d tree, %d-bit records, %d nodes, built %s", arg[i],
      md.database_type ~= "" and md.database_type or "MMDB", reader.ip_version, reader.record_size,
      reader.node_count, md.build_epoch and os.date("!%Y-%m-%d", md.build_epoch) or "unknown"))
    reader:close()
  end
end
os.exit(status)
