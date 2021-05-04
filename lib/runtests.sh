#!/bin/bash


# for file in tests/*; do
# 	LD_LIBRARY_PATH=../deps/lua-memory/src:$LD_LIBRARY_PATH LUA_CPATH='../deps/lua-memory/src/?.so;;' lua $file > /dev/null
# 	echo "File $file executed with no errors"
# done

LD_LIBRARY_PATH=../deps/lua-memory/src:$LD_LIBRARY_PATH LUA_CPATH='../deps/lua-memory/src/?.so;;' lua test.lua