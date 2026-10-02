# Contributing

Thank you for helping. Bug reports, documentation fixes and code are all welcome.

## Before you start

- For anything larger than a small fix, open an issue first to agree on the approach.
- Report security problems privately, as described in [SECURITY.md](SECURITY.md).
- Keep the plugin dependency-free and the request path free of network calls and file opens.

## Development setup

You need LuaJIT 2.1 (OpenResty's), LuaRocks, `busted`, `luacheck` and `luafilesystem`. Kong's own packages
provide LuaJIT, LuaRocks and `resty`. [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) describes the layout,
tools and test layers.

```sh
luarocks install busted 2.2.0
luarocks install luacheck 1.2.0
luarocks install luafilesystem
```

## Checks every pull request must pass

```sh
luacheck .                    # no warnings
busted                        # unit tests
pongo run spec/integration    # Kong's harness (Docker); or rely on CI
python3 spec/e2e/e2e.py       # if you changed the handler, headers or registry
```

## Guidelines

- Add or update tests with every change. Fixtures must be synthetic and use documentation address space
  (RFC 5737, RFC 3849) and documentation AS numbers (RFC 5398). Tests must not need network access or API
  keys.
- Fields come from verified IPGeolocation.io schemas only. To add or change one, edit
  `kong/plugins/ipgeolocation/fields.lua`, extend the fixtures and tests, keep names consistent with the
  Traefik plugin, and regenerate the reference: `resty -I . tools/gen-fields-doc.lua > docs/FIELDS.md`.
- Configuration changes need schema validation, a README table entry and a CHANGELOG entry.
- Match the existing style: two-space indentation, local functions, no globals, lines up to 120 characters
  where practical.
- Note user-visible changes under "Unreleased" in [CHANGELOG.md](CHANGELOG.md).

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
