local utils = {}

function utils.get_table_from_string(table_string)
	return load('return ' .. table_string)()
end

function utils.split_text_into_chunks(text, chunk_size)
	local s = {}
	for i=1, #text, chunk_size do
		s[#s+1] = text:sub(i, i + chunk_size - 1)
	end
	return s
end

return utils