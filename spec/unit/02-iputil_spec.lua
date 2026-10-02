local iputil = require "kong.plugins.ipgeolocation.iputil"

describe("iputil", function()
  it("parses IPv4", function()
    local b, n, text = iputil.parse("203.0.113.7")
    assert.same({ 203, 0, 113, 7 }, b)
    assert.equal(4, n)
    assert.equal("203.0.113.7", text)
  end)

  it("parses IPv6 in all notations", function()
    local cases = {
      ["2001:db8::1"] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
      ["::1"] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
      ["::"] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
      ["2001:DB8:0:0:0:0:0:FFFF"] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff },
      ["fe80::1%eth0"] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
      ["1:2:3:4:5:6:7::"] = { 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 0 },
      ["::2:0:0"] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0 },
      ["64:ff9b::192.0.2.33"] = { 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 33 },
    }
    for ip, expected in pairs(cases) do
      local b, n = iputil.parse(ip)
      assert.equal(16, n, ip)
      assert.same(expected, b, ip)
    end
    local _, _, text = iputil.parse("2001:DB8::A")
    assert.equal("2001:db8::a", text)
  end)

  it("normalises IPv4-mapped IPv6 to IPv4", function()
    local b, n, text = iputil.parse("::ffff:203.0.113.10")
    assert.equal(4, n)
    assert.same({ 203, 0, 113, 10 }, b)
    assert.equal("203.0.113.10", text)
    b, n = iputil.parse("::FFFF:cb00:710a")
    assert.equal(4, n)
    assert.same({ 203, 0, 113, 10 }, b)
    -- IPv4-compatible (deprecated) and NAT64 addresses are not rewritten
    assert.equal(16, select(2, iputil.parse("::203.0.113.10")))
    assert.equal(16, select(2, iputil.parse("64:ff9b::203.0.113.10")))
  end)

  it("rejects malformed addresses", function()
    for _, bad in ipairs({
      "", "1", "256.1.1.1", "1.2.3", "1.2.3.4.5", "1.2.3.-4", " 1.2.3.4", "1.2.3.4 ",
      "1::2::3", ":::", "12345::", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "::g", "unix:",
      "unix:/var/run/kong.sock", "::ffff:999.0.0.1", "1.2.3.4/24", ":1::",
    }) do
      assert.is_nil((iputil.parse(bad)), bad)
    end
    assert.is_nil((iputil.parse(nil)))
    assert.is_nil((iputil.parse(42)))
  end)

  it("classifies private, loopback and link-local addresses like the Traefik plugin", function()
    local private = {
      "10.1.2.3", "127.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.10.1",
      "100.64.0.1", "100.127.255.255", "0.0.0.0", "224.0.0.251", "::1", "::", "fd00::1", "fc00::1",
      "fe80::1", "febf::1", "ff02::1",
    }
    local public = {
      "203.0.113.1", "8.8.8.8", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1",
      "192.169.0.1", "2001:db8::1", "fec0::1", "ff05::1", "::2",
    }
    for _, ip in ipairs(private) do
      local b, n = iputil.parse(ip)
      assert.is_true(iputil.is_private(b, n), ip)
    end
    for _, ip in ipairs(public) do
      local b, n = iputil.parse(ip)
      assert.is_false(iputil.is_private(b, n), ip)
    end
  end)

  it("matches CIDRs on bit boundaries", function()
    local function m(cidr, ip)
      local c = assert(iputil.parse_cidr(cidr))
      local b, n = iputil.parse(ip)
      return iputil.cidr_match(c, b, n)
    end
    assert.is_true(m("203.0.113.0/24", "203.0.113.255"))
    assert.is_false(m("203.0.113.0/24", "203.0.114.0"))
    assert.is_true(m("10.0.0.0/9", "10.127.255.255"))
    assert.is_false(m("10.0.0.0/9", "10.128.0.0"))
    assert.is_true(m("0.0.0.0/0", "8.8.8.8"))
    assert.is_true(m("203.0.113.7", "203.0.113.7"))
    assert.is_false(m("203.0.113.7", "203.0.113.8"))
    assert.is_true(m("2001:db8::/33", "2001:db8:7fff::1"))
    assert.is_false(m("2001:db8::/33", "2001:db8:8000::1"))
    assert.is_false(m("2001:db8::/32", "203.0.113.1"))
    assert.is_true(m("::ffff:203.0.113.0/120", "203.0.113.9"))
    assert.is_nil((iputil.parse_cidr("10.0.0.0/33")))
    assert.is_nil((iputil.parse_cidr("nope/8")))
    assert.is_nil((iputil.parse_cidr("::ffff:1.2.3.4/64")))
  end)
end)
