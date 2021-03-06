local messenger = require'lunatik_messenger'
local utils = require'utils'

local LunatikState = {}

local LunatikStateMt = {
	name = "",
	currAlloc = 0,
	maxalloc = 0
}

function LunatikStateMt:new (o)

	o = o or {}
	setmetatable(o, self)
	self.__index = self

	return o
end

function LunatikStateMt:dostring(code)

	if type(code) ~= 'string' then
		return nil, 'code must be string'
	end

	local fragment_size = messenger.constants.LUNATIK_FRAGMENT_SIZE

	local code_chunks = utils.split_text_into_chunks(code, fragment_size)

	local response_table = nil

	for k, v in pairs(code_chunks) do
		local frag_msg = string.format([[
			{
				name = %q,
				code_size = %d,
				fragment = %q,
				fragment_size = %d,
				fragment_index = %d,
				fragment_amount = %d,
				operation = %d
			}
		]], self.name, string.len(code), v, string.len(v), k, #code_chunks, messenger.operations.DO_STRING)

		local ok, kernel_response = messenger.send( frag_msg )

		print(frag_msg)
		if not ok then
			return nil, 'Failed to send msg to kernel'
		end

		response_table = utils.get_table_from_string( kernel_response )

		if not response_table.operation_success then
			return nil, response_table.response
		end
	end

	return true, response_table.response
end

function LunatikStateMt:put()

	local msg = string.format([[
		{
			name = %q,
			operation = %d
		}
	]], self.name, messenger.operations.PUT_STATE)

	local ok, kernel_response = messenger.send(msg)

	if not ok then
		return nil, 'Failed to send message to kernel'
	end

	self.name = ""
	self.curralloc = 0
	self.maxalloc = 0

	local response_table = utils.get_table_from_string(kernel_response)

	return response_table.operation_success, response_table.response
end

function LunatikState.new_state(name, maxalloc)

	if type(name) ~= 'string' then
		return nil, 'state name must be a string'
	end

	if type(maxalloc) == 'nil' then
		maxalloc = messenger.constants.LUNATIK_MIN_ALLOC_BYTES
	elseif type(maxalloc) ~= 'number' then
		return nil, 'maxalloc must be nil or number'
	end

	if string.len(name) >= messenger.constants.LUNATIK_NAME_MAXSIZE then
		return nil, 'state name is bigger than the maximum allowed'
	end

	local msg = string.format([[
		{
			operation = %d,
			name = %q,
			maxalloc = %d
		}
	]], messenger.operations.CREATE_STATE, name, maxalloc)

	local ok, kernel_response = messenger.send(msg)

	if not ok then
		return nil, 'Failed to send message to kernel'
	end

	local response_table = utils.get_table_from_string(kernel_response)

	if not response_table.operation_success then
		return nil, response_table.response
	end

	return true, LunatikStateMt:new{
		name = name,
		maxalloc = maxalloc,
		curralloc = response_table.curr_alloc
	}
end

function LunatikState.get_state(state_name)
	if type(state_name) ~= 'string' then
		return nil, 'state name must be a string'
	end

	if string.len(state_name) >= messenger.constants.LUNATIK_NAME_MAXSIZE then
		return nil, 'state name longer than the maximum allowed'
	end

	local msg = string.format([[
		{
			state_name = %q,
			operation = %d
		}
	]], state_name, messenger.operations.GET_STATE)

	local ok, kernel_response = messenger.send(msg)

	if not ok then
		return nil, 'Failed to put msg to kernel'
	end

	local response_table = utils.get_table_from_string(kernel_response)

	if response_table.operation_success == false then
		return nil, response_table.response
	end

	return true, LunatikStateMt:new{
		name = response_table.state_name,
		curralloc = response_table.curr_alloc,
		maxalloc = response_table.max_alloc
	}
end

function LunatikState.list()
	local result = {}

	local msg = string.format([[
		{
			init = true,
			operation = %d
		}
	]], messenger.operations.LIST_STATES)

	local ok, kernel_response = messenger.send(msg)

	if not ok then
		return nil, 'Failed to send message to list states to kernel'
	end

	local response_table = utils.get_table_from_string(kernel_response)

	local states_amount = response_table.states_amount

	for i = 0, states_amount - 1 do
		msg = string.format( [[
			{
				curr_state_to_get = %d,
				init = false,
				operation = %d
			}
		]], i, messenger.operations.LIST_STATES)

		ok, kernel_response = messenger.send(msg)

		if not ok then
			print('Failed to send msg to get ' .. i .. 'th state')
		end

		response_table = utils.get_table_from_string(kernel_response)

		if response_table.operation_success == false then
			print('Failed executing the list states operation')
		end

		result[#result + 1] = response_table.response

	end

	return result
end

return LunatikState