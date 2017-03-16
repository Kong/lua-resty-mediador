local bind  = require "spec.helper"
local proxy = require "resty.mediador.proxy"


local find        = string.find
local insert      = table.insert


local function create_req (socket_addr, headers)
  return {
    connection = {remote_address=socket_addr},
    headers    = (headers or {})
  }
end

local function all ()
  return true
end

local function none ()
  return false
end

local function trust10x (addr)
  return find(addr, '10.', 1, true) == 1
end

describe('forwarded(req)', function()

  local forwarded, req

  setup(function()
    forwarded, req = proxy.forwarded, {}
  end)

  teardown(function()
    forwarded, req = nil, nil
  end)

  before_each(function()
    req = {}
  end)

  it('should require req', function()
    assert.has_error(forwarded, 'argument req is required')
  end)

  it('should work with X-Forwarded-For header', function()
    req = create_req('127.0.0.1')
    assert.same(forwarded(req), {'127.0.0.1'})
  end)

  it('should include entries from X-Forwarded-For', function()
    req = create_req('127.0.0.1', {
      ['x-forwarded-for'] = '10.0.0.2, 10.0.0.1'
    })
    assert.same(forwarded(req), {'127.0.0.1', '10.0.0.1', '10.0.0.2'})
  end)

  it('should skip blank entries', function()
    req = create_req('127.0.0.1', {
      ['x-forwarded-for'] = '10.0.0.2,, 10.0.0.1'
    })
    assert.same(forwarded(req), {'127.0.0.1', '10.0.0.1', '10.0.0.2'})
  end)
end)

describe('proxyaddr(req, trust)', function ()

  local proxyaddr, req

  teardown(function ()
    proxyaddr, req = nil, nil
  end)

  setup(function ()
    proxyaddr, req = proxy, {}
  end)

  before_each(function ()
    req = {}
  end)

  describe('arguments', function ()
    describe('req', function ()
      it('should be required', function ()
        assert.has_error(proxyaddr, 'req argument is required')
      end)
    end)

    describe('trust', function ()
      it('should be required', function ()
        req = create_req('127.0.0.1')
        assert.has_error(bind(proxyaddr, req), 'trust argument is required')
      end)

      it('should accept a function', function ()
        req = create_req('127.0.0.1')
        assert.not_error(bind(proxyaddr, req, all))
      end)

      it('should accept an array', function ()
        req = create_req('127.0.0.1')
        assert.not_error(bind(proxyaddr, req, {}))
      end)

      it('should accept a string', function ()
        req = create_req('127.0.0.1')
        assert.not_error(bind(proxyaddr, req, '127.0.0.1'))
      end)

      it('should reject a number', function ()
        req = create_req('127.0.0.1')
        assert.has_error(bind(proxyaddr, req, 42), 'unsupported trust argument')
      end)

      it('should accept IPv4', function ()
        req = create_req('127.0.0.1')
        assert.not_error(bind(proxyaddr, req, '127.0.0.1'))
      end)

      it('should accept IPv6', function ()
        req = create_req('127.0.0.1')
        assert.not_error(bind(proxyaddr, req, '::1'))
      end)

      it('should accept IPv4-style IPv6', function ()
        req = create_req('127.0.0.1')
        assert.not_error(bind(proxyaddr, req, '::ffff:127.0.0.1'))
      end)

      it('should accept pre-defined names', function ()
        req = create_req('127.0.0.1')
        assert.not_error(bind(proxyaddr, req, 'loopback'))
      end)

      it('should accept pre-defined names in array', function ()
        req = create_req('127.0.0.1')
        assert.not_error(bind(proxyaddr, req, {'loopback', '10.0.0.1'}))
      end)

      it('should reject non-IP', function ()
        req = create_req('127.0.0.1')
        assert.has_error(bind(proxyaddr, req, 'blargh'),        'invalid IP address: blargh')
        assert.has_error(bind(proxyaddr, req, '10.0.300.1/16'), 'invalid IP address: 10.0.300.1')
        assert.has_error(bind(proxyaddr, req, '-1'),            'invalid IP address: -1')
      end)

      it('should reject bad CIDR', function ()
        req = create_req('127.0.0.1')
        assert.has_error(bind(proxyaddr, req, '::1/6000'), 'invalid range on address: ::1/6000')
        assert.has_error(
          bind(proxyaddr, req, '10.0.0.1/internet'), 'invalid range on address: 10.0.0.1/internet'
        )
        assert.has_error(
          bind(proxyaddr, req, '10.0.0.1/6000'), 'invalid range on address: 10.0.0.1/6000'
        )
        assert.has_error(
          bind(proxyaddr, req, '::ffff:a00:2/46'), 'invalid range on address: ::ffff:a00:2/46'
        )
      end)

      it('should be invoked as trust(addr, i)', function ()
        local log = {}
        req       = create_req('127.0.0.1', {
          ['x-forwarded-for'] = '192.168.0.1, 10.0.0.1'
        })

        proxyaddr(req, function (addr, i)
          insert(log, {addr, i}) return #log
        end)

        assert.same(log, {{'127.0.0.1', 1}, {'10.0.0.1', 2}})
      end)
    end)
  end)

  describe('with all trusted', function ()
    it('should return socket address with no headers', function ()
      req = create_req('127.0.0.1')
      assert.equal(proxyaddr(req, all), '127.0.0.1')
    end)

    it('should return header value', function ()
      req = create_req('127.0.0.1', {
        ['x-forwarded-for'] = '10.0.0.1'
      })
      assert.equal(proxyaddr(req, all), '10.0.0.1')
    end)

    it('should return furthest header value', function ()
      req = create_req('127.0.0.1', {
        ['x-forwarded-for'] = '10.0.0.1, 10.0.0.2'
      })
      assert.equal(proxyaddr(req, all), '10.0.0.1')
    end)
  end)

  describe('with none trusted', function ()
    it('should return socket address with no headers', function ()
      req = create_req('127.0.0.1')
      assert.equal(proxyaddr(req, none), '127.0.0.1')
    end)

    it('should return socket address with headers', function ()
      req = create_req('127.0.0.1', {
        ['x-forwarded-for'] = '10.0.0.1, 10.0.0.2'
      })
      assert.equal(proxyaddr(req, none), '127.0.0.1')
    end)
  end)

  describe('with some trusted', function ()
    it('should return socket address with no headers', function ()
      req = create_req('127.0.0.1')
      assert.equal(proxyaddr(req, trust10x), '127.0.0.1')
    end)

    it('should return socket address when not trusted', function ()
      req = create_req('127.0.0.1', {
        ['x-forwarded-for'] = '10.0.0.1, 10.0.0.2'
      })
      assert.equal(proxyaddr(req, trust10x), '127.0.0.1')
    end)

    it('should return header when socket trusted', function ()
      req = create_req('10.0.0.1', {
        ['x-forwarded-for'] = '192.168.0.1'
      })
      assert.equal(proxyaddr(req, trust10x), '192.168.0.1')
    end)

    it('should return first untrusted after trusted', function ()
      req = create_req('10.0.0.1', {
        ['x-forwarded-for'] = '192.168.0.1, 10.0.0.2'
      })
      assert.equal(proxyaddr(req, trust10x), '192.168.0.1')
    end)

    it('should not skip untrusted', function ()
      req = create_req('10.0.0.1', {
        ['x-forwarded-for'] = '10.0.0.3, 192.168.0.1, 10.0.0.2'
      })
      assert.equal(proxyaddr(req, trust10x), '192.168.0.1')
    end)
  end)

  describe('when given array', function ()
    it('should accept literal IP addresses', function ()
      req = create_req('10.0.0.1', {
        ['x-forwarded-for'] = '192.168.0.1, 10.0.0.2'
      })
      assert.equal(proxyaddr(req, {'10.0.0.1', '10.0.0.2'}), '192.168.0.1')
    end)

    it('should not trust non-IP addresses', function ()
      req = create_req('10.0.0.1', {
        ['x-forwarded-for'] = '192.168.0.1, 10.0.0.2, localhost'
      })
      assert.equal(proxyaddr(req, {'10.0.0.1', '10.0.0.2'}), 'localhost')
    end)

    it('should return socket address if none match', function ()
      req = create_req('10.0.0.1', {
        ['x-forwarded-for'] = '192.168.0.1, 10.0.0.2'
      })
      assert.equal(proxyaddr(req, {'127.0.0.1', '192.168.0.100'}), '10.0.0.1')
    end)

    describe('when array empty', function ()
      it('should return socket address ', function ()
        req = create_req('127.0.0.1')
        assert.equal(proxyaddr(req, {}), '127.0.0.1')
      end)

      it('should return socket address with headers', function ()
        req = create_req('127.0.0.1', {
          ['x-forwarded-for'] = '10.0.0.1, 10.0.0.2'
        })
        assert.equal(proxyaddr(req, {}), '127.0.0.1')
      end)
    end)
  end)

  describe('when given IPv4 addresses', function ()
    it('should accept literal IP addresses', function ()
      req = create_req('10.0.0.1', {
        ['x-forwarded-for'] = '192.168.0.1, 10.0.0.2'
      })
      assert.equal(proxyaddr(req, {'10.0.0.1', '10.0.0.2'}), '192.168.0.1')
    end)

    it('should accept CIDR notation', function ()
      req = create_req('10.0.0.1', {
        ['x-forwarded-for'] = '192.168.0.1, 10.0.0.200'
      })
      assert.equal(proxyaddr(req, '10.0.0.2/26'), '10.0.0.200')
    end)

    it('should accept netmask notation', function ()
      req = create_req('10.0.0.1', {
        ['x-forwarded-for'] = '192.168.0.1, 10.0.0.200'
      })
      assert.equal(proxyaddr(req, '10.0.0.2/255.255.255.192'), '10.0.0.200')
    end)
  end)

  describe('when given IPv6 addresses', function ()
    it('should accept literal IP addresses', function ()
      req = create_req('fe80::1', {
        ['x-forwarded-for'] = '2002:c000:203::1, fe80::2'
      })
      assert.equal(proxyaddr(req, {'fe80::1', 'fe80::2'}), '2002:c000:203::1')
    end)

    it('should accept CIDR notation', function ()
      req = create_req('fe80::1', {
        ['x-forwarded-for'] = '2002:c000:203::1, fe80::ff00'
      })
      assert.equal(proxyaddr(req, 'fe80::/125'), 'fe80::ff00')
    end)

    it('should accept netmask notation', function ()
      req = create_req('fe80::1', {
        ['x-forwarded-for'] = '2002:c000:203::1, fe80::ff00'
      })
      assert.equal(
        proxyaddr(req, 'fe80::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff8'), 'fe80::ff00'
      )
    end)
  end)

  describe('when IP versions mixed', function ()
    it('should match respective versions', function ()
      req = create_req('::1', {
        ['x-forwarded-for'] = '2002:c000:203::1'
      })
      assert.equal(proxyaddr(req, {'127.0.0.1', '::1'}), '2002:c000:203::1')
    end)

    it('should not match IPv4 to IPv6', function ()
      req = create_req('::1', {
        ['x-forwarded-for'] = '2002:c000:203::1'
      })
      assert.equal(proxyaddr(req, '127.0.0.1'), '::1')
    end)
  end)

  describe('when IPv4-mapped IPv6 addresses', function ()
    it('should match IPv4 trust to IPv6 request', function ()
      req = create_req('::ffff:a00:1', {
        ['x-forwarded-for'] = '192.168.0.1, 10.0.0.2'
      })
      assert.equal(proxyaddr(req, {'10.0.0.1', '10.0.0.2'}), '192.168.0.1')
    end)

    it('should match IPv4 netmask trust to IPv6 request', function ()
      req = create_req('::ffff:a00:1', {
        ['x-forwarded-for'] = '192.168.0.1, 10.0.0.2'
      })
      assert.equal(proxyaddr(req, {'10.0.0.1/16'}), '192.168.0.1')
    end)

    it('should match IPv6 trust to IPv4 request', function ()
      req = create_req('10.0.0.1', {
        ['x-forwarded-for'] = '192.168.0.1, 10.0.0.2'
      })
      assert.equal(proxyaddr(req, {'::ffff:a00:1', '::ffff:a00:2'}), '192.168.0.1')
    end)

    it('should match CIDR notation for IPv4-mapped address', function ()
      req = create_req('10.0.0.1', {
        ['x-forwarded-for'] = '192.168.0.1, 10.0.0.200'
      })
      assert.equal(proxyaddr(req, '::ffff:a00:2/122'), '10.0.0.200')
    end)

    it('should match subnet notation for IPv4-mapped address', function ()
      req = create_req('10.0.0.1', {
        ['x-forwarded-for'] = '192.168.0.1, 10.0.0.200'
      })
      assert.equal(
        proxyaddr(req, '::ffff:a00:2/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffc0'),
        '10.0.0.200'
      )
    end)
  end)

  describe('when given pre-defined names', function ()
    it('should accept single pre-defined name', function ()
      req = create_req('fe80::1', {
        ['x-forwarded-for'] = '2002:c000:203::1, fe80::2'
      })
      assert.equal(proxyaddr(req, 'linklocal'), '2002:c000:203::1')
    end)

    it('should accept multiple pre-defined names', function ()
      req = create_req('::1', {
        ['x-forwarded-for'] = '2002:c000:203::1, fe80::2'
      })
      assert.equal(proxyaddr(req, {'loopback', 'linklocal'}), '2002:c000:203::1')
    end)
  end)

  describe('when header contains non-ip addresses', function ()
    it('should stop at first non-ip after trusted', function ()
      req = create_req('127.0.0.1', {
        ['x-forwarded-for'] = 'myrouter, 127.0.0.1, proxy'
      })
      assert.equal(proxyaddr(req, '127.0.0.1'), 'proxy')
    end)

    it('should provide all values to function', function ()
      local log = {}
      req       = create_req('127.0.0.1', {
        ['x-forwarded-for'] = 'myrouter, 127.0.0.1, proxy'
      })

      proxyaddr(req, function (addr, i)
        insert(log, {addr, i}) return #log
      end)

      assert.same(log, {
        {'127.0.0.1', 1}, {'proxy', 2}, {'127.0.0.1', 3}
      })
    end)
  end)
end)

describe('proxyaddr.all(req, [trust])', function ()

  local proxyall, req

  setup(function ()
    proxyall, req = proxy.all, {}
  end)

  teardown(function ()
    proxyall, req = nil, nil
  end)

  before_each(function ()
    req = {}
  end)

  describe('arguments', function ()
    describe('req', function ()
      it('should be required', function ()
        assert.has_error(proxyall, 'argument req is required')
      end)
    end)

    describe('trust', function ()
      it('should be optional', function ()
        req = create_req('127.0.0.1')
        assert.not_error(bind(proxyall, req))
      end)
    end)
  end)

  describe('with no headers', function ()
    it('should return socket address', function()
      req = create_req('127.0.0.1')
      assert.same(proxyall(req), {'127.0.0.1'})
    end)
  end)

  describe('with x-forwarded-for header', function ()
    it('should include x-forwarded-for', function ()
      req = create_req('127.0.0.1', {
        ['x-forwarded-for'] = '10.0.0.1'
      })
      assert.same(proxyall(req), {'127.0.0.1', '10.0.0.1'})
    end)

    it('should include x-forwarded-for in correct order', function ()
      req = create_req('127.0.0.1', {
        ['x-forwarded-for'] = '10.0.0.1, 10.0.0.2'
      })
      assert.same(proxyall(req), {'127.0.0.1', '10.0.0.2', '10.0.0.1'})
    end)
  end)

  describe('with trust argument', function ()
    it('should stop at first untrusted', function ()
      req = create_req('127.0.0.1', {
        ['x-forwarded-for'] = '10.0.0.1, 10.0.0.2'
      })
      assert.same(proxyall(req, '127.0.0.1'), {'127.0.0.1', '10.0.0.2'})
    end)

    it('should be only socket address for no trust', function ()
      req = create_req('127.0.0.1', {
        ['x-forwarded-for'] = '10.0.0.1, 10.0.0.2'
      })
      assert.same(proxyall(req, {}), {'127.0.0.1'})
    end)
  end)
end)

describe('proxyaddr.compile(trust)', function ()

  local compile

  setup(function ()
    compile = proxy.compile
  end)

  teardown(function ()
    compile = nil
  end)

  describe('arguments', function ()
    describe('trust', function ()
      it('should be required', function ()
        assert.has_error(bind(compile), 'argument is required')
      end)

      it('should accept an array', function ()
        assert.is.Function(compile({}))
      end)

      it('should accept a string', function ()
        assert.is.Function(compile('127.0.0.1'))
      end)

      it('should reject a number', function ()
        assert.has_error(bind(compile, 42), 'unsupported trust argument')
      end)

      it('should accept IPv4', function ()
        assert.is.Function(compile('127.0.0.1'))
      end)

      it('should accept IPv6', function ()
        assert.is.Function(compile('::1'))
      end)

      it('should accept IPv4-style IPv6', function ()
        assert.is.Function(compile('::ffff:127.0.0.1'))
      end)

      it('should accept pre-defined names', function ()
        assert.is.Function(compile('loopback'))
      end)

      it('should accept pre-defined names in array', function ()
        assert.is.Function(compile({'loopback', '10.0.0.1'}))
      end)

      it('should accept zero CIDR', function ()
        assert.is.Function(compile({'0.0.0.0/0', '::/0'}))
        assert.is.Function(compile('0.0.0.0/0'))
        assert.is.Function(compile('::/0'))
      end)

      it('should reject non-IP', function ()
        assert.has_error(bind(compile, 'blargh'), 'invalid IP address: blargh')
        assert.has_error(bind(compile, '-1'),     'invalid IP address: -1')
      end)

      it('should reject bad CIDR', function ()
        assert.has_error(bind(compile, '::1/6000'),         'invalid range on address: ::1/6000')
        assert.has_error(bind(compile, '10.0.0.1/6000'),    'invalid range on address: 10.0.0.1/6000')
        assert.has_error(bind(compile, '::ffff:a00:2/136'), 'invalid range on address: ::ffff:a00:2/136')
        assert.has_error(bind(compile, '::ffff:a00:2/46'),  'invalid range on address: ::ffff:a00:2/46')
      end)

    end)
  end)
end)
