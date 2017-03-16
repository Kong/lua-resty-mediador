--
-- Mediador, determine address of proxied request
--
-- @author    leite (xico@simbio.se)
-- @license   MIT
-- @copyright Simbiose 2015
--
-- Modifications by Aapo Talvensaari, Mashape, Inc., 2017

local string, table, math, ip_addr, bit_available, bit =
  require [[string]], require [[table]], require [[math]], require [[mediador.ip]], pcall(require, 'bit')

-- yey! Lua 5.3 bitwise keywords available
if _VERSION == 'Lua 5.3' then
  bit = not bit_available and {} or bit
  assert(load([[
    math.pow   = function (a, b) return a ^ b end
    bit.band   = bit.band or function (a, b) return a & b end
    bit.lshift = bit.lshift ot function (a, b) return a << b end
  ]], nil, nil, {bit = bit, math = math}))()
end

local type, tonumber, assert, setmetatable, format, match, gmatch, insert, remove, pow, band, lshift,
  isip, parse_ip =
  type, tonumber, assert, setmetatable, string.format, string.match, string.gmatch, table.insert,
  table.remove, math.pow, bit.band, bit.lshift, ip_addr.valid, ip_addr.parse

--

local ipranges, EMPTY = {
  linklocal   = {'169.254.0.0/16', 'fe80::/10'},
  loopback    = {'127.0.0.1/8', '::1/128'},
  uniquelocal = {'10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'}
}, ''

string, table, math, bit, ip_addr = nil, nil, nil, nil, nil

-- splice table
--
-- @table  destiny
-- @number index
-- @number replaces
-- @table  source
-- @return table

local function splice (destiny, index, replaces, source)
  local chopped = {}
  replaces      = replaces or 1

  if not destiny[index] or not destiny[(index + replaces) - 1] then
    return chopped
  end

  for _ = index, (index + replaces) - 1 do
    insert(chopped, remove(destiny, index))
  end

  if source then
    for i = #source, 1, -1 do
      insert(destiny, index, source[i])
    end
  end

  return chopped
end

-- get all addresses in the request, using the `X-Forwarded-For` header
--
-- @table  req
-- @return table

local function forwarded (req)
  assert(req, 'argument req is required')

  local addrs = {req.connection.remote_address}

  for addr in gmatch((req.headers['x-forwarded-for'] or ''), '%s*([^,$]+)%s*,?') do
    insert(addrs, 2, addr)
  end

  return addrs
end

-- parse netmask string into CIDR range.
--
-- @string note
-- @return number

local function parse_netmask (netmask)
  local ip          = parse_ip(netmask)
  local parts, size = ip.octets, 8

  if 'ipv6' == ip:kind() then
    parts, size = ip.parts, 16
  end

  local max, range = pow(2, size) - 1, 0

  for i = 1, #parts do
    local part = band(parts[i], max)

    if max == part then
      range = range + size
    else
      while part > 0 do
        part  = band(lshift(part, 1), max)
        range = range + 1
      end
      break
    end
  end

  return range
end

-- parse IP notation string into range subnet.
--
-- @string note
-- @return ip, number

local function parse_ip_notation (note)
  local ip, range = match(note, '^([^/]+)/([^$]+)$')
  ip = (not ip or EMPTY == ip) and note or ip

  assert(isip(ip), format('invalid IP address: %s', ip))

  ip   = parse_ip(ip)
  local kind = ip:kind()
  local max  = 'ipv6' == kind and 128 or 32

  if not range or EMPTY == range then
    range = max
  else
    range = tonumber(range) and tonumber(range) or
      (isip(range) and parse_netmask(range) or 0)
  end

  if 'ipv6' == kind and ip:is_ipv4_mapped() then
    ip    = ip:ipv4_address()
    range = range <= max and range - 96 or range
  end

  assert(range >= 0 and range <= max, format('invalid range on address: %s', note))

  return ip, range
end

-- static trust function to trust nothing.
--
-- @return boolean

local function trust_none ()
  return false
end

-- compile trust function for single subnet.
--
-- @table  subnet
-- @return function

local function trust_single (subnet)
  local subnet_ip, subnet_range = subnet[1], subnet[2]
  local subnet_kind             = subnet_ip:kind()
  local subnet_isipv4           = subnet_kind == 'ipv4'

  local function _trust (addr)
    if not(isip(addr)) then
      return false
    end

    local ip   = parse_ip(addr)
    local kind = ip:kind()

    return kind == subnet_kind and
      ip:match(subnet_ip, subnet_range) or
      ((subnet_isipv4 and kind == 'ipv6' and ip:is_ipv4_mapped()) and
        ip:ipv4_address():match(subnet_ip, subnet_range) or false)
  end
  return _trust
end

-- compile trust function for multiple subnets.
--
-- @table subnets
-- @return function

local function trust_multi (subnets)
  local function _trust (addr)

    if not(isip(addr)) then
      return false
    end

    local ip = parse_ip(addr)
    local kind, ipv4 = ip:kind()

    for i = 1, #subnets do
      local skip
      local subnet                  = subnets[i]
      local subnet_ip, subnet_range = subnet[1], subnet[2]
      local subnet_kind, trusted    = subnet_ip:kind(), ip

      if kind ~= subnet_kind then
        if 'ipv6' ~= kind or 'ipv4' ~= subnet_kind or not ip:is_ipv4_mapped() then
          skip = true
        else
          ipv4    = ipv4 or ip:ipv4_address()
          trusted = ipv4
        end
      end

      if not skip and trusted:match(subnet_ip, subnet_range) then
        return true
      end
    end
    return false
  end
  return _trust
end

-- compile `table` elements into range subnets.
--
-- @table  table
-- @return table

local function compile_range_subnets (table)
  local range_subnets = {}

  for i = 1, #table do
    range_subnets[i] = {parse_ip_notation(table[i])}
  end

  return range_subnets
end

-- compile range subnet array into trust function.
--
-- @table  range_subnets
-- @return function

local function compile_trust (range_subnets)
  local lx = #range_subnets
  return lx == 0 and trust_none or
    (lx == 1 and trust_single(range_subnets[1]) or trust_multi(range_subnets))
end

--
-- compile argument into trust function.
--
-- @param  val
-- @return function

local function compile (val)
  assert(val, 'argument is required')

  local trust, val, _type, i = {}, val, type(val), 1
  if 'string' == _type then
    trust = {val}
  else
    assert('table' == _type, 'unsupported trust argument')
    trust = val
  end

  while trust[i] do
    if ipranges[trust[i]] then
      val = ipranges[trust[i]]
      splice(trust, i, 1, val)
      i = i + #val - 1
    else
      i = i + 1
    end
  end

  return compile_trust(compile_range_subnets(trust))
end

--
-- get all addresses in the request, optionally stopping at the first untrusted.
--
-- @table  req
-- @param  trust
-- @return table

local function alladdrs (req, trust)
  local addrs = forwarded(req)

  if not trust then
    return addrs
  end

  if 'function' ~= type(trust) then
    trust = compile(trust)
  end

  local size, should, result = #addrs, false, {}
  for i = 1, #addrs do
    if should then
      break
    end
    insert(result, addrs[i])
    if i == size or not trust(addrs[i], i)  then
      should = true
    end
  end

  return result
end

-- determine address of proxied request.
--
-- @table  self
-- @table  req
-- @param  trust
-- @return string

local function proxyaddr (_, req, trust)
  assert(req,   'req argument is required')
  assert(trust, 'trust argument is required')

  local addrs = alladdrs(req, trust)
  local addr  = addrs[#addrs]

  return addr
end

-- mediador metatable

local mediador_mt = {
  forwarded = forwarded,
  all       = alladdrs,
  compile   = compile,
  __call    = proxyaddr
}

mediador_mt.__index = mediador_mt

return setmetatable({}, mediador_mt)