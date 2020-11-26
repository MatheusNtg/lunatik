local lunatik = require'lunatik'
local memory = require'memory'
local session = lunatik.session()

local buffer = memory.create(3)
memory.set(buffer, 1, 0x65, 0x66, 0x67)

-- TODO the kscript variable starts with \n, if such variable starts with \t then a kernel panic along with a deadlock will occour
local kscript = [[
	function receive_callback(mem)
		print'A memory has been received'
		memory.tostring(mem)
	end
]]

local s1 = session:newstate's1'

local err = s1:dostring(kscript, 'send script')

err = s1:send(buffer)

s1:close()
