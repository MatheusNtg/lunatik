local messenger = require'lunatik_messenger'
local lunatik = {}

local function get_table_from_string(table_string)
	return load('return ' .. table_string)()
end

local LunatikState = {
	name = "",
	currAlloc = 0,
	maxalloc = 0
}

function LunatikState:new (o)

	o = o or {}
	setmetatable(o, self)
	self.__index = self

	return o
end

function lunatik.new_state(name, maxalloc)

	msg = string.format([[
		msg = {
			operation = %d,
			name = "%s",
			maxalloc = %d
		}
	]], messenger.operations.CREATE_STATE, name, maxalloc)

	ok, kernel_response = messenger.send(msg)

	response_table = get_table_from_string(kernel_response)

	if not response_table.operation_success then
		return nil, response_table.response
	end

	if not ok then
		return nil, response_table.response
	end

	return true, LunatikState:new{
		name = name,
		maxalloc = maxalloc,
		currAlloc = response_table.curr_alloc
	}

end

return lunatik