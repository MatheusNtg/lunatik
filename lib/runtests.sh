#!/bin/bash

set -e

#for file in tests/*; do
for i in {1..100}; do
	echo "Running #$i"
#	echo "Running $file"
	LD_LIBRARY_PATH=../deps/lua-memory/src LUA_CPATH='../deps/lua-memory/src/?.so;;' lua tests/simple_send.lua
#	echo "$file executed with no errors!"
#done
done
