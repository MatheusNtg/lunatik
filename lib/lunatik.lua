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

function LunatikState:dostring(code)
	code = "[[" .. code .. "]]"
	local msg = string.format([[
		msg = {
			name = "%s",
			code = %s,
			operation = %d
		}
	]],self.name, code, messenger.operations.DO_STRING)

	local ok, kernel_response = messenger.send(msg)

	if not ok then
		return nil, 'Failed to send message to kernel'
	end

	local response_table = get_table_from_string(kernel_response)

	return response_table.operation_success, response_table.response
end

function LunatikState:putstate()
	local msg = string.format([[
		msg = {
			name = "%s",
			operation = %d
		}
	]], self.name, messenger.operations.PUT_STATE)

	local ok, kernel_response = messenger.send(msg)

	if not ok then
		return nil, 'Failed to send message to kernel'
	end

	local response_table = get_table_from_string(kernel_response)

	return response_table.operation_success, response_table.response
	

end

function lunatik.new_state(name, maxalloc)

	local msg = string.format([[
		msg = {
			operation = %d,
			name = "%s",
			maxalloc = %d
		}
	]], messenger.operations.CREATE_STATE, name, maxalloc)

	local ok, kernel_response = messenger.send(msg)

	
	if not ok then
		return nil, 'Failed to send message to kernel'
	end
	
	local response_table = get_table_from_string(kernel_response)

	if not response_table.operation_success then
		return nil, response_table.response
	end
	
	return true, LunatikState:new{
		name = name,
		maxalloc = maxalloc,
		currAlloc = response_table.curr_alloc
	}

end

return lunatik