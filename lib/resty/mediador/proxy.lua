--
-- Mediador, determine address of proxied request
--
-- @author    leite (xico@simbio.se)
-- @license   MIT
-- @copyright Simbiose 2015, Mashape, Inc. 2017

local bit = require "bit"
local ip  = require "resty.mediador.ip"


local table        = table
local math         = math
local type         = type
local tonumber     = tonumber
local assert       = assert
local setmetatable = setmetatable
local format       = string.format
local insert       = table.insert
local remove       = table.remove
local pow          = math.pow
local band         = bit.band
local lshift       = bit.lshift
local ipvalid      = ip.valid
local ipparse      = ip.parse


local match_note
local match_forwarded


do
  if ngx then
    local match  = ngx.re.match
    local gmatch = ngx.re.gmatch
    local unpack = table.unpack or unpack

    local ok, new = pcall(require, "table.new")
    if not ok then
      new = function() return {} end
    end

    local note_captures  = new(2, 0)

    match_note = function(note)
      if match(note, "([^/]+)/([^$]+)$", "ajos", nil, note_captures) then
        return unpack(note_captures)
      end
    end

    match_forwarded = function(xf)
      local i = gmatch(xf or "", [[\s*([^,$]+)\s*,?]], "jos")
      if i then
        return function()
          local c = i()
          if c then
            return c[1]
          end
        end
      end
    end

  else
    local match  = string.match
    local gmatch = string.gmatch

    match_note = function(note)
      return match(note, "^([^/]+)/([^$]+)$")
    end

    match_forwarded = function(xf)
      return gmatch(xf or "", "%s*([^,$]+)%s*,?")
    end
  end
end


local EMPTY   = ""
local RANGES  = {
  linklocal   = { "169.254.0.0/16", "fe80::/10" },
  loopback    = { "127.0.0.1/8", "::1/128" },
  uniquelocal = { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7" }
}

-- splice table
--
-- @table  destiny
-- @number index
-- @number replaces
-- @table  source
-- @return table

local function splice(destiny, index, replaces, source)
  local chopped = {}
  replaces      = replaces or 1

  if not destiny[index] or not destiny[index + replaces - 1] then
    return chopped
  end

  for _ = index, index + replaces - 1 do
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
-- @string remote
-- @string xf
-- @return table

local function forwarded(remote, xf)
  assert(remote, "argument remote is required")

  local addrs = { remote }

  for addr in match_forwarded(xf) do
    insert(addrs, 2, addr)
  end

  return addrs
end

-- parse netmask string into CIDR range.
--
-- @string note
-- @return number

local function parse_netmask(netmask)
  local addr = ipparse(netmask)
  local parts, size = addr.octets, 8

  if "ipv6" == addr:kind() then
    parts, size = addr.parts, 16
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

local function parse_ip_notation(note)
  local addr, range = match_note(note)
  addr = (not addr or EMPTY == addr) and note or addr

  assert(ipvalid(addr), format("invalid IP address: %s", addr))

  addr = ipparse(addr)
  local kind = addr:kind()
  local max  = "ipv6" == kind and 128 or 32

  if not range or EMPTY == range then
    range = max
  else
    range = tonumber(range) and tonumber(range) or
      (ipvalid(range) and parse_netmask(range) or -1)
  end

  if "ipv6" == kind and addr:is_ipv4_mapped() then
    addr = addr:ipv4_address()
    range = range <= max and range - 96 or range
  end

  assert(range >= 0 and range <= max, format("invalid range on address: %s", note))

  return addr, range
end

-- static trust function to trust nothing.
--
-- @return boolean

local function trust_none()
  return false
end

-- compile trust function for single subnet.
--
-- @table  subnet
-- @return function

local function trust_single(subnet)
  local subnet_ip, subnet_range = subnet[1], subnet[2]
  local subnet_kind             = subnet_ip:kind()
  local subnet_isipv4           = subnet_kind == "ipv4"

  local function _trust(address)
    if not(ipvalid(address)) then
      return false
    end

    local addr = ipparse(address)
    local kind = addr:kind()

    return kind == subnet_kind and
      addr:match(subnet_ip, subnet_range) or
      ((subnet_isipv4 and kind == "ipv6" and addr:is_ipv4_mapped()) and
        addr:ipv4_address():match(subnet_ip, subnet_range) or false)
  end
  return _trust
end

-- compile trust function for multiple subnets.
--
-- @table subnets
-- @return function

local function trust_multi(subnets)
  local function _trust(address)
    if not(ipvalid(address)) then
      return false
    end

    local addr = ipparse(address)
    local kind, ipv4 = addr:kind()

    for i = 1, #subnets do
      local skip
      local subnet                  = subnets[i]
      local subnet_ip, subnet_range = subnet[1], subnet[2]
      local subnet_kind, trusted    = subnet_ip:kind(), addr

      if kind ~= subnet_kind then
        if "ipv6" ~= kind or "ipv4" ~= subnet_kind or not addr:is_ipv4_mapped() then
          skip = true
        else
          ipv4    = ipv4 or addr:ipv4_address()
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

-- compile `subnets` elements into range subnets.
--
-- @table  subnets
-- @return table

local function compile_range_subnets(subnets)
  local range_subnets = {}

  for i = 1, #subnets do
    range_subnets[i] = { parse_ip_notation(subnets[i]) }
  end

  return range_subnets
end

-- compile range subnet array into trust function.
--
-- @table  range_subnets
-- @return function

local function compile_trust(range_subnets)
  local lx = #range_subnets
  return lx == 0 and trust_none or
    (lx == 1 and trust_single(range_subnets[1]) or trust_multi(range_subnets))
end

--
-- compile argument into trust function.
--
-- @param  val
-- @return function

local function compile(val)
  assert(val, "argument is required")

  local trust
  local value, _type, i = val, type(val), 1
  if "string" == _type then
    trust = { value }
  else
    assert("table" == _type, "unsupported trust argument")
    trust = value
  end

  while trust[i] do
    if RANGES[trust[i]] then
      value = RANGES[trust[i]]
      splice(trust, i, 1, value)
      i = i + #value - 1
    else
      i = i + 1
    end
  end

  return compile_trust(compile_range_subnets(trust))
end

--
-- get all addresses in the request, optionally stopping at the first untrusted.
--
-- @string remote
-- @string xf
-- @param  trust
-- @return table

local function alladdrs(remote, xf, trust)
  local addrs = forwarded(remote, xf)

  if not trust then
    return addrs
  end

  if "function" ~= type(trust) then
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
-- @string remote
-- @string xf
-- @param  trust
-- @return string

local function proxyaddr(_, remote, xf, trust)
  assert(remote, "remote argument is required")
  assert(trust,   "trust argument is required")

  local addrs = alladdrs(remote, xf, trust)
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
