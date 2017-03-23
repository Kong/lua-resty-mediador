local bind  = require "spec.helper"
local proxy = require "resty.mediador.proxy"


local find      = string.find
local insert    = table.insert
local forwarded = proxy.forwarded
local proxyall  = proxy.all
local compile   = proxy.compile


local function all ()
  return true
end

local function none ()
  return false
end

local function trust10x (addr)
  return find(addr, "10.", 1, true) == 1
end


describe("forwarded(remote, xf)", function()

  it("should require remote", function()
    assert.has_error(forwarded, "argument remote is required")
  end)

  it("should work with X-Forwarded-For header", function()
    assert.same(forwarded("127.0.0.1"), {"127.0.0.1"})
  end)

  it("should include entries from X-Forwarded-For", function()
    assert.same(forwarded("127.0.0.1", "10.0.0.2, 10.0.0.1"), {"127.0.0.1", "10.0.0.1", "10.0.0.2"})
  end)

  it("should skip blank entries", function()
    assert.same(forwarded("127.0.0.1", "10.0.0.2,, 10.0.0.1"), {"127.0.0.1", "10.0.0.1", "10.0.0.2"})
  end)

end)

describe("proxy(remote, xf, trust)", function()

  describe("arguments", function()
    describe("remote", function()
      it("should be required", function()
        assert.has_error(proxy, "remote argument is required")
      end)
    end)

    describe("trust", function()
      it("should be required", function()
        assert.has_error(bind(proxy, "127.0.0.1"), "trust argument is required")
      end)

      it("should accept a function", function()
        assert.not_error(bind(proxy, "127.0.0.1", nil, all))
      end)

      it("should accept an array", function()
        assert.not_error(bind(proxy, "127.0.0.1", nil, {}))
      end)

      it("should accept a string", function()
        assert.not_error(bind(proxy, "127.0.0.1", nil, "127.0.0.1"))
      end)

      it("should reject a number", function()
        assert.has_error(bind(proxy, "127.0.0.1", nil, 42), "unsupported trust argument")
      end)

      it("should accept IPv4", function()
        assert.not_error(bind(proxy, "127.0.0.1", nil, "127.0.0.1"))
      end)

      it("should accept IPv6", function()
        assert.not_error(bind(proxy, "127.0.0.1", nil, "::1"))
      end)

      it("should accept IPv4-style IPv6", function()
        assert.not_error(bind(proxy, "127.0.0.1", nil, "::ffff:127.0.0.1"))
      end)

      it("should accept pre-defined names", function()
        assert.not_error(bind(proxy, "127.0.0.1", nil, "loopback"))
      end)

      it("should accept pre-defined names in array", function()
        assert.not_error(bind(proxy, "127.0.0.1", nil, {"loopback", "10.0.0.1"}))
      end)

      it("should reject non-IP", function()
        assert.has_error(bind(proxy, "127.0.0.1", nil, "blargh"),        "invalid IP address: blargh")
        assert.has_error(bind(proxy, "127.0.0.1", nil, "10.0.300.1/16"), "invalid IP address: 10.0.300.1")
        assert.has_error(bind(proxy, "127.0.0.1", nil, "-1"),            "invalid IP address: -1")
      end)

      it("should reject bad CIDR", function()
        assert.has_error(bind(proxy, "127.0.0.1", nil, "::1/6000"), "invalid range on address: ::1/6000")
        assert.has_error(
          bind(proxy, "127.0.0.1", nil, "10.0.0.1/internet"), "invalid range on address: 10.0.0.1/internet"
        )
        assert.has_error(
          bind(proxy, "127.0.0.1", nil, "10.0.0.1/6000"), "invalid range on address: 10.0.0.1/6000"
        )
        assert.has_error(
          bind(proxy, "127.0.0.1", nil, "::ffff:a00:2/46"), "invalid range on address: ::ffff:a00:2/46"
        )
      end)

      it("should be invoked as trust(addr, i)", function()
        local log = {}
        proxy("127.0.0.1", "192.168.0.1, 10.0.0.1", function(addr, i)
          insert(log, {addr, i}) return #log
        end)
        assert.same(log, {{"127.0.0.1", 1}, {"10.0.0.1", 2}})
      end)
    end)
  end)

  describe("with all trusted", function()
    it("should return socket address with no headers", function()
      assert.equal(proxy("127.0.0.1", nil, all), "127.0.0.1")
    end)

    it("should return header value", function()
      assert.equal(proxy("127.0.0.1", "10.0.0.1", all), "10.0.0.1")
    end)

    it("should return furthest header value", function()
      assert.equal(proxy("127.0.0.1", "10.0.0.1, 10.0.0.2", all), "10.0.0.1")
    end)
  end)

  describe("with none trusted", function()
    it("should return socket address with no headers", function()
      assert.equal(proxy("127.0.0.1", nil, none), "127.0.0.1")
    end)

    it("should return socket address with headers", function()
      assert.equal(proxy("127.0.0.1", "10.0.0.1, 10.0.0.2", none), "127.0.0.1")
    end)
  end)

  describe("with some trusted", function()
    it("should return socket address with no headers", function()
      assert.equal(proxy("127.0.0.1", nil, trust10x), "127.0.0.1")
    end)

    it("should return socket address when not trusted", function()
      assert.equal(proxy("127.0.0.1", "10.0.0.1, 10.0.0.2", trust10x), "127.0.0.1")
    end)

    it("should return header when socket trusted", function()
      assert.equal(proxy("10.0.0.1", "192.168.0.1", trust10x), "192.168.0.1")
    end)

    it("should return first untrusted after trusted", function()
      assert.equal(proxy("10.0.0.1", "192.168.0.1, 10.0.0.2", trust10x), "192.168.0.1")
    end)

    it("should not skip untrusted", function()
      assert.equal(proxy("10.0.0.1", "10.0.0.3, 192.168.0.1, 10.0.0.2", trust10x), "192.168.0.1")
    end)
  end)

  describe("when given array", function()
    it("should accept literal IP addresses", function()
      assert.equal(proxy("10.0.0.1", "192.168.0.1, 10.0.0.2", {"10.0.0.1", "10.0.0.2"}), "192.168.0.1")
    end)

    it("should not trust non-IP addresses", function()
      assert.equal(proxy("10.0.0.1", "192.168.0.1, 10.0.0.2, localhost", {"10.0.0.1", "10.0.0.2"}), "localhost")
    end)

    it("should return socket address if none match", function()
      assert.equal(proxy("10.0.0.1", "192.168.0.1, 10.0.0.2", {"127.0.0.1", "192.168.0.100"}), "10.0.0.1")
    end)

    describe("when array empty", function()
      it("should return socket address ", function()
        assert.equal(proxy("127.0.0.1", nil, {}), "127.0.0.1")
      end)

      it("should return socket address with headers", function()
        assert.equal(proxy("127.0.0.1", "10.0.0.1, 10.0.0.2", {}), "127.0.0.1")
      end)
    end)
  end)

  describe("when given IPv4 addresses", function()
    it("should accept literal IP addresses", function()
      assert.equal(proxy("10.0.0.1", "192.168.0.1, 10.0.0.2", {"10.0.0.1", "10.0.0.2"}), "192.168.0.1")
    end)

    it("should accept CIDR notation", function()
      assert.equal(proxy("10.0.0.1", "192.168.0.1, 10.0.0.200", "10.0.0.2/26"), "10.0.0.200")
    end)

    it("should accept netmask notation", function()
      assert.equal(proxy("10.0.0.1", "192.168.0.1, 10.0.0.200", "10.0.0.2/255.255.255.192"), "10.0.0.200")
    end)
  end)

  describe("when given IPv6 addresses", function()
    it("should accept literal IP addresses", function()
      assert.equal(proxy("fe80::1", "2002:c000:203::1, fe80::2", {"fe80::1", "fe80::2"}), "2002:c000:203::1")
    end)

    it("should accept CIDR notation", function()
      assert.equal(proxy("fe80::1", "2002:c000:203::1, fe80::ff00", "fe80::/125"), "fe80::ff00")
    end)

    it("should accept netmask notation", function()
      assert.equal(
        proxy("fe80::1", "2002:c000:203::1, fe80::ff00", "fe80::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff8"), "fe80::ff00"
      )
    end)
  end)

  describe("when IP versions mixed", function()
    it("should match respective versions", function()
      assert.equal(proxy("::1", "2002:c000:203::1", {"127.0.0.1", "::1"}), "2002:c000:203::1")
    end)

    it("should not match IPv4 to IPv6", function()
      assert.equal(proxy("::1", "2002:c000:203::1", "127.0.0.1"), "::1")
    end)
  end)

  describe("when IPv4-mapped IPv6 addresses", function()
    it("should match IPv4 trust to IPv6 request", function()
      assert.equal(proxy("::ffff:a00:1", "192.168.0.1, 10.0.0.2", {"10.0.0.1", "10.0.0.2"}), "192.168.0.1")
    end)

    it("should match IPv4 netmask trust to IPv6 request", function()
      assert.equal(proxy("::ffff:a00:1", "192.168.0.1, 10.0.0.2", {"10.0.0.1/16"}), "192.168.0.1")
    end)

    it("should match IPv6 trust to IPv4 request", function()
      assert.equal(proxy("10.0.0.1", "192.168.0.1, 10.0.0.2", {"::ffff:a00:1", "::ffff:a00:2"}), "192.168.0.1")
    end)

    it("should match CIDR notation for IPv4-mapped address", function()
      assert.equal(proxy("10.0.0.1", "192.168.0.1, 10.0.0.200", "::ffff:a00:2/122"), "10.0.0.200")
    end)

    it("should match subnet notation for IPv4-mapped address", function()
      assert.equal(
        proxy("10.0.0.1", "192.168.0.1, 10.0.0.200", "::ffff:a00:2/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffc0"), "10.0.0.200")
    end)
  end)

  describe("when given pre-defined names", function()
    it("should accept single pre-defined name", function()
      assert.equal(proxy("fe80::1", "2002:c000:203::1, fe80::2", "linklocal"), "2002:c000:203::1")
    end)

    it("should accept multiple pre-defined names", function()
      assert.equal(proxy("::1", "2002:c000:203::1, fe80::2", {"loopback", "linklocal"}), "2002:c000:203::1")
    end)
  end)

  describe("when header contains non-ip addresses", function()
    it("should stop at first non-ip after trusted", function()
      assert.equal(proxy("127.0.0.1", "myrouter, 127.0.0.1, proxy", "127.0.0.1"), "proxy")
    end)

    it("should provide all values to function", function()
      local log = {}
      proxy("127.0.0.1", "myrouter, 127.0.0.1, proxy", function(addr, i)
        insert(log, {addr, i}) return #log
      end)

      assert.same(log, {
        {"127.0.0.1", 1}, {"proxy", 2}, {"127.0.0.1", 3}
      })
    end)
  end)
end)

describe("proxy.all(remote, xf, [trust])", function()

  describe("arguments", function()
    describe("remote", function()
      it("should be required", function()
        assert.has_error(proxyall, "argument remote is required")
      end)
    end)

    describe("trust", function()
      it("should be optional", function()
        assert.not_error(bind(proxyall, "127.0.0.1"))
      end)
    end)
  end)

  describe("with no headers", function()
    it("should return socket address", function()
      assert.same(proxyall("127.0.0.1"), {"127.0.0.1"})
    end)
  end)

  describe("with x-forwarded-for header", function()
    it("should include x-forwarded-for", function()
      assert.same(proxyall("127.0.0.1", "10.0.0.1"), {"127.0.0.1", "10.0.0.1"})
    end)

    it("should include x-forwarded-for in correct order", function()
      assert.same(proxyall("127.0.0.1", "10.0.0.1, 10.0.0.2"), {"127.0.0.1", "10.0.0.2", "10.0.0.1"})
    end)
  end)

  describe("with trust argument", function()
    it("should stop at first untrusted", function()
      assert.same(proxyall("127.0.0.1", "10.0.0.1, 10.0.0.2", "127.0.0.1"), {"127.0.0.1", "10.0.0.2"})
    end)

    it("should be only socket address for no trust", function()
      assert.same(proxyall("127.0.0.1", "10.0.0.1, 10.0.0.2", {}), {"127.0.0.1"})
    end)
  end)

end)

describe("proxy.compile(trust)", function()

  describe("arguments", function()
    describe("trust", function()
      it("should be required", function()
        assert.has_error(bind(compile), "argument is required")
      end)

      it("should accept an array", function()
        assert.is.Function(compile({}))
      end)

      it("should accept a string", function()
        assert.is.Function(compile("127.0.0.1"))
      end)

      it("should reject a number", function()
        assert.has_error(bind(compile, 42), "unsupported trust argument")
      end)

      it("should accept IPv4", function()
        assert.is.Function(compile("127.0.0.1"))
      end)

      it("should accept IPv6", function()
        assert.is.Function(compile("::1"))
      end)

      it("should accept IPv4-style IPv6", function()
        assert.is.Function(compile("::ffff:127.0.0.1"))
      end)

      it("should accept pre-defined names", function()
        assert.is.Function(compile("loopback"))
      end)

      it("should accept pre-defined names in array", function()
        assert.is.Function(compile({"loopback", "10.0.0.1"}))
      end)

      it("should accept zero CIDR", function()
        assert.is.Function(compile({"0.0.0.0/0", "::/0"}))
        assert.is.Function(compile("0.0.0.0/0"))
        assert.is.Function(compile("::/0"))
      end)

      it("should reject non-IP", function()
        assert.has_error(bind(compile, "blargh"), "invalid IP address: blargh")
        assert.has_error(bind(compile, "-1"),     "invalid IP address: -1")
      end)

      it("should reject bad CIDR", function()
        assert.has_error(bind(compile, "::1/6000"),         "invalid range on address: ::1/6000")
        assert.has_error(bind(compile, "10.0.0.1/6000"),    "invalid range on address: 10.0.0.1/6000")
        assert.has_error(bind(compile, "::ffff:a00:2/136"), "invalid range on address: ::ffff:a00:2/136")
        assert.has_error(bind(compile, "::ffff:a00:2/46"),  "invalid range on address: ::ffff:a00:2/46")
      end)

      it("should compile and but not match zero ip", function()
        assert.is.Function(compile("0.0.0.0"))
        assert.is.False(compile("0.0.0.0")("127.0.0.1"))
      end)

      it("should compile and but not match zero ip array", function()
        assert.is.Function(compile{"::", "0.0.0.0"})
        assert.is.False(compile{"::", "0.0.0.0"}("127.0.0.1"))
      end)

      it("should compile and match zero subnet", function()
        assert.is.Function(compile("0.0.0.0/0"))
        assert.is.True(compile("0.0.0.0/0")("127.0.0.1"))
      end)

      it("should compile and match zero subnet array", function()
        assert.is.Function(compile{"::/0", "0.0.0.0/0"})
        assert.is.True(compile({"::/0", "0.0.0.0/0"})("127.0.0.1"))
      end)

      it("should compile and match exact IPv4 address", function()
        assert.is.Function(compile("127.0.0.1"))
        assert.is.True(compile("127.0.0.1")("127.0.0.1"))
      end)

      it("should compile and match exact IPv4 address array", function()
        assert.is.Function(compile{"127.0.0.1", "127.0.0.1"})
        assert.is.True(compile{"127.0.0.1", "127.0.0.1"}("127.0.0.1"))
      end)

      it("should compile and match exact IPv6 address", function()
        assert.is.Function(compile("::1"))
        assert.is.True(compile("::1")("::1"))
      end)

      it("should compile and match exact IPv6 address array", function()
        assert.is.Function(compile{"::1"})
        assert.is.True(compile{"::1", "::1"}("::1"))
      end)

      it("should compile and match exact IPv6 address (expanded 1)", function()
        assert.is.Function(compile("::1"))
        assert.is.True(compile("0:0:0:0:0:0:0:1")("::1"))
      end)

      it("should compile and match exact IPv6 address (expanded 2)", function()
        assert.is.Function(compile("::1"))
        assert.is.True(compile("::1")("0:0:0:0:0:0:0:1"))
      end)
    end)
  end)

end)
