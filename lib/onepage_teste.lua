local lunatik = require'lunatik'

local script = [[
	print'Olá do módulo'
]]

local controller = lunatik.control()

controller:create'teste'

controller:execute('teste', script)

controller:destroy'teste'
