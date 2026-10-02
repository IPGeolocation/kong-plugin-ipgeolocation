-- Configuration schema.
--
-- Database paths are validated syntactically only. Their existence is
-- deliberately not checked here: in hybrid mode and Konnect the control
-- plane validates configuration but the files live on the data planes. Data
-- planes report missing or invalid databases in their error log and apply
-- `policy.fail_open`.

local typedefs = require "kong.db.schema.typedefs"
local fields = require "kong.plugins.ipgeolocation.fields"
local iputil = require "kong.plugins.ipgeolocation.iputil"

local CONTINENTS = { "AF", "AN", "AS", "EU", "NA", "OC", "SA" }

-- Headers that must never be produced by this plugin.
local RESERVED_HEADERS = {
  ["host"] = true, ["content-length"] = true, ["content-type"] = true,
  ["transfer-encoding"] = true, ["connection"] = true, ["keep-alive"] = true,
  ["proxy-connection"] = true, ["proxy-authorization"] = true, ["te"] = true,
  ["trailer"] = true, ["upgrade"] = true, ["expect"] = true,
  ["authorization"] = true, ["cookie"] = true,
}

local function validate_path(path)
  if path:sub(1, 1) ~= "/" then
    return nil, "must be an absolute path"
  end
  if #path > 4096 then
    return nil, "path is too long"
  end
  if path:find("%c") then
    return nil, "must not contain control characters"
  end
  if path:sub(-1) == "/" then
    return nil, "must be the path of a file, not a directory"
  end
  for segment in path:gmatch("[^/]+") do
    if segment == ".." then
      return nil, "must not contain '..' segments"
    end
  end
  return true
end

local function validate_asn(value)
  if value:match("^[Aa][Ss]%d+$") or value:match("^%d+$") then
    return true
  end
  return nil, "must be an autonomous system number such as AS15169 or 15169"
end

local function validate_header_name(name)
  if #name > 128 then
    return nil, "header name is too long"
  end
  if not name:match("^[%w!#%$%%&'%*%+%-%.%^_`|~]+$") then
    return nil, "'" .. name .. "' is not a valid header name"
  end
  if RESERVED_HEADERS[name:lower()] then
    return nil, "'" .. name .. "' cannot be set by this plugin"
  end
  return true
end

local function exclusive(p, a, b)
  local x, y = p[a], p[b]
  if type(x) == "table" and type(y) == "table" and #x > 0 and #y > 0 then
    return nil, "set either policy." .. a .. " or policy." .. b .. ", not both"
  end
  return true
end

local function validate_config(config)
  local interval = config.database_refresh_interval
  if interval and interval ~= 0 and interval < 60 then
    return nil, "database_refresh_interval must be 0 (disabled) or at least 60 seconds"
  end

  local h = config.headers
  if type(h) == "table" then
    if type(h.list_separator) == "string" and h.list_separator:find("%c") then
      return nil, "headers.list_separator must not contain control characters"
    end
    if type(h.custom) == "table" then
      for name, field in pairs(h.custom) do
        local ok, err = validate_header_name(name)
        if not ok then
          return nil, "headers.custom: " .. err
        end
        if field ~= "" and not fields.is_field(field) then
          return nil, "headers.custom: '" .. name .. "' refers to unknown field '" .. tostring(field)
                      .. "' (see the README for the field reference)"
        end
      end
    end
  end

  local p = config.policy
  if type(p) == "table" then
    for _, pair in ipairs({
      { "allowed_countries", "blocked_countries" },
      { "allowed_continents", "blocked_continents" },
      { "allowed_asns", "blocked_asns" },
    }) do
      local ok, err = exclusive(p, pair[1], pair[2])
      if not ok then
        return nil, err
      end
    end
    -- Kong's ip_or_cidr accepts entries the plugin cannot match, such as
    -- IPv4-mapped prefixes shorter than /96 (::ffff:10.0.0.0/8). Reject
    -- them here instead of failing on every request.
    if type(p.exempt_ips) == "table" then
      for _, cidr in ipairs(p.exempt_ips) do
        local ok, err = iputil.parse_cidr(cidr)
        if not ok then
          return nil, "policy.exempt_ips: invalid entry '" .. tostring(cidr) .. "': " .. err
        end
      end
    end
  end

  return true
end

local function flag(description)
  return { description = description, type = "boolean", required = true, default = false }
end

local function country_list(description)
  return {
    description = description,
    type = "array",
    required = true,
    default = {},
    elements = { type = "string", match = "^%a%a$" },
  }
end

local function continent_list(description)
  return {
    description = description,
    type = "array",
    required = true,
    default = {},
    elements = { type = "string", one_of = CONTINENTS },
  }
end

local function asn_list(description)
  return {
    description = description,
    type = "array",
    required = true,
    default = {},
    elements = { type = "string", custom_validator = validate_asn },
  }
end

return {
  name = "ipgeolocation",
  fields = {
    -- The plugin runs before authentication (priority 2450), so a consumer
    -- is never known when it executes.
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { databases = {
              description = "Ordered list of absolute paths to IPGeolocation.io MMDB files. For each field the first database that holds a value wins, so a Location and a Security database (or a bundle) layer without further configuration.",
              type = "array",
              required = true,
              len_min = 1,
              len_max = 16,
              elements = { type = "string", custom_validator = validate_path },
          } },
          { database_refresh_interval = {
              description = "Seconds between checks for updated database files (0 disables; minimum 60). Changed files are validated before they replace the database in service. Files must be replaced atomically (rename), never rewritten in place.",
              type = "integer",
              required = true,
              default = 0,
              between = { 0, 604800 },
          } },
          { headers = {
              type = "record",
              required = true,
              fields = {
                { preset = {
                    description = "Request headers to add: none, minimal (country, city, ASN), standard (15 headers) or full (every bounded field plus X-IPGeo-IP).",
                    type = "string",
                    required = true,
                    default = "minimal",
                    one_of = { "none", "minimal", "standard", "full" },
                } },
                { custom = {
                    description = "Header name to field name map applied on top of the preset. An empty field name removes a header the preset added.",
                    type = "map",
                    required = true,
                    default = {},
                    keys = { type = "string" },
                    values = { type = "string", len_min = 0, len_max = 64 },
                } },
                { boolean_format = {
                    description = "How booleans appear in headers: true_false (true/false, Traefik default) or one_zero (1/0, Nginx module format).",
                    type = "string",
                    required = true,
                    default = "true_false",
                    one_of = { "true_false", "one_zero" },
                } },
                { list_separator = {
                    description = "Separator used to join list values such as provider names.",
                    type = "string",
                    required = true,
                    default = ",",
                    len_min = 1,
                    len_max = 8,
                } },
                { language = {
                    description = "Language for country, region, city, continent and currency names; falls back to English.",
                    type = "string",
                    required = true,
                    default = "en",
                    one_of = fields.LANGUAGES,
                } },
                { max_value_length = {
                    description = "Maximum length of a header value in bytes; longer values are truncated on a UTF-8 boundary.",
                    type = "integer",
                    required = true,
                    default = 1024,
                    between = { 16, 8192 },
                } },
              },
          } },
          { policy = {
              type = "record",
              required = true,
              fields = {
                { allowed_countries = country_list("Only these ISO 3166-1 alpha-2 countries are allowed.") },
                { blocked_countries = country_list("These ISO 3166-1 alpha-2 countries are blocked.") },
                { allowed_continents = continent_list("Only these continents are allowed (AF, AN, AS, EU, NA, OC, SA).") },
                { blocked_continents = continent_list("These continents are blocked.") },
                { allowed_asns = asn_list("Only these autonomous systems are allowed (AS15169 or 15169).") },
                { blocked_asns = asn_list("These autonomous systems are blocked.") },
                { block_tor = flag("Block Tor exit nodes (is_tor).") },
                { block_vpn = flag("Block VPN addresses (is_vpn).") },
                { block_proxy = flag("Block proxies (is_proxy).") },
                { block_relay = flag("Block relays such as iCloud Private Relay (is_relay).") },
                { block_residential_proxy = flag("Block residential proxies (is_residential_proxy).") },
                { block_anonymous = flag("Block anonymised addresses (is_anonymous).") },
                { block_known_attacker = flag("Block known attackers (is_known_attacker).") },
                { block_bot = flag("Block bots (is_bot). Known good bots such as search engine crawlers are spared unless block_known_good_bots is set.") },
                { block_known_good_bots = flag("Make block_bot apply to known good bots too.") },
                { block_spam = flag("Block known spam sources (is_spam).") },
                { block_cloud_provider = flag("Block cloud and hosting provider addresses (is_cloud_provider).") },
                { block_corporate_gateway = flag("Block corporate egress gateways (is_corporate_gateway).") },
                { block_threat_score_above = {
                    description = "Block when threat_score is greater than this value (0-100). Unset disables the rule.",
                    type = "integer",
                    between = { 0, 100 },
                } },
                { exempt_ips = {
                    description = "Addresses or CIDRs exempt from every policy rule (still enriched). Use the ip-restriction plugin to deny addresses.",
                    type = "array",
                    required = true,
                    default = {},
                    elements = typedefs.ip_or_cidr,
                } },
                { allow_private = {
                    description = "Pass private, loopback and link-local addresses without lookup or headers.",
                    type = "boolean",
                    required = true,
                    default = true,
                } },
                { allow_unknown = {
                    description = "When an allow list is set and the value (country, continent, ASN) is unknown, allow the request.",
                    type = "boolean",
                    required = true,
                    default = true,
                } },
                { fail_open = {
                    description = "When a database is unavailable or a lookup fails, allow the request (true) or block it (false).",
                    type = "boolean",
                    required = true,
                    default = true,
                } },
                { dry_run = {
                    description = "Evaluate and log rules without blocking; adds X-IPGeo-Dry-Run with the reason to the upstream request.",
                    type = "boolean",
                    required = true,
                    default = false,
                } },
                { status_code = {
                    description = "HTTP status returned to blocked clients.",
                    type = "integer",
                    required = true,
                    default = 403,
                    between = { 400, 599 },
                } },
                { message = {
                    description = "Message returned to blocked clients. The block reason is never disclosed.",
                    type = "string",
                    required = true,
                    default = "Access denied",
                    len_min = 1,
                    len_max = 512,
                } },
              },
          } },
          { log_serialize = {
              description = "Add the lookup result and policy decision to Kong's log serializer under 'ipgeolocation', for log plugins such as http-log and file-log.",
              type = "boolean",
              required = true,
              default = false,
          } },
        },
        custom_validator = validate_config,
      },
    },
  },
}
