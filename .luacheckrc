std = "ngx_lua"
unused_args = false
redefined = false
max_line_length = 160

globals = {
  "kong",
  "ngx",
}

files["spec/**/*.lua"] = {
  std = "ngx_lua+busted",
  globals = { "kong", "ngx" },
  -- test fixtures are long data tables
  max_line_length = false,
}

files["kong/plugins/ipgeolocation/fields.lua"] = {
  -- the catalog is one field definition per line
  max_line_length = false,
}

files["kong/plugins/ipgeolocation/schema.lua"] = {
  -- field descriptions
  max_line_length = false,
}

files["tools/*.lua"] = {
  globals = { "arg" },
}

exclude_files = {
  ".pongo/**",
  "servroot/**",
}
