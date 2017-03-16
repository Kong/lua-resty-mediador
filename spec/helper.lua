-- a simple busted tests helper
--
-- @author    leite (xico@simbio.se)
-- @license   MIT
-- @copyright Simbiose 2015

local table, say, util, assert =
  require [[table]], require [[say]], require [[luassert.util]], require [[luassert.assert]]

local unpack, remove, insert, deep_cmp =
  table.unpack or unpack, util.tremove, util.tinsert, util.deepcompare

-- remove ?!
--
-- @table  args
-- @number index
-- @return boolean

local function final_swap(args, index)
  --insert(args, 1, args[index])
  remove(args, index + 1)
  return false
end

-- compare a string with a two return variables function
--
-- @table  state
-- @table  args
-- @return boolean

local function safe_equals(state, args)
  assert(args.n > 2, say('assertion.internal.argtolittle', {'safe_equals', 3, tostring(args.n)}))
  assert(
    'boolean' == type(args[2]),
    say('assertion.internal.badargtype', {2, 'safe_equals', 'boolean', type(args[2])})
  )
  assert(args[2] == true, say('assertion.error.negative', {args[3]}))

  if args[1] ~= args[3] then
    return final_swap(args, 1)
  end

  return true
end

-- compare a table with a two return variables function
--
-- @table  state
-- @table  args
-- @return boolean

local function safe_same(state, args)
  assert(args.n > 2, say('assertion.internal.argtolittle', {'safe_same', 3, tostring(args.n)}))
  assert(
    'boolean' == type(args[2]),
    say('assertion.internal.badargtype', {2, 'safe_same', 'boolean', type(args[2])})
  )
  assert(args[2] == true, say('assertion.error.negative', {args[3]}))

  if 'table' == type(args[1]) and 'table' == type(args[3]) then
    if not deep_cmp(args[3], args[1], true) then
      return final_swap(args, 1)
    end
  else
    if args[1] ~= args[3] then
      return final_swap(args, 1)
    end
  end

  return true
end

-- compare a failure status with a two return variables function
--
-- @table  state
-- @table  args
-- @return boolean

local function safe_fail(state, args)
  assert(args.n > 2, say('assertion.internal.argtolittle', {'safe_fail', 3, tostring(args.n)}))
  assert(
    'boolean' == type(args[2]),
    say('assertion.internal.badargtype', {2, 'safe_fail', 'boolean', type(args[1])})
  )
  assert(args[3] == args[1], say('assertion.error.positive', {args[3], args[1]}))
  return true
end

say:set('assertion.safe_equals.positive', 'Expected %s\n to be equals \n%s')
say:set('assertion.safe_same.positive',   'Expected %s\n to be same as \n%s')
say:set('assertion.safe_fail.positive',   'Expected %s\n to fail like \n%s')

assert:register(
  'assertion', 'safeequals', safe_equals,
  'assertion.safe_equals.positive', 'assertion.equals.negative'
)
assert:register(
  'assertion', 'safesame', safe_same,
  'assertion.safe_same.positive', 'assertion.same.negative'
)
assert:register('assertion', 'safefail', safe_fail, 'assertion.safe_equals.positive')

-- bind function
--
-- @function fn
-- @mix ...
-- @return function

return function(fn, ...)
  local args = {...}
  return function()
    fn(unpack(args))
  end
end