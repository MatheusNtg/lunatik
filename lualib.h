/*
** $Id: lualib.h,v 1.23 2002/06/05 17:24:04 roberto Exp roberto $
** Lua standard libraries
** See Copyright Notice in lua.h
*/


#ifndef lualib_h
#define lualib_h

#include "lua.h"


#ifndef LUALIB_API
#define LUALIB_API	extern
#endif


#define LUA_ALERT               "_ALERT"

#define LUA_COLIBNAME	"coroutine"
LUALIB_API int lua_baselibopen (lua_State *L);

#define LUA_TABLIBNAME	"table"
LUALIB_API int lua_tablibopen (lua_State *L);

#define LUA_IOLIBNAME	"io"
#define LUA_OSLIBNAME	"os"
LUALIB_API int lua_iolibopen (lua_State *L);

#define LUA_STRLIBNAME	"string"
LUALIB_API int lua_strlibopen (lua_State *L);

#define LUA_MATHLIBNAME	"math"
LUALIB_API int lua_mathlibopen (lua_State *L);

#define LUA_DBLIBNAME	"debug"
LUALIB_API int lua_dblibopen (lua_State *L);


/* to help testing the libraries */
#ifndef lua_assert
#define lua_assert(c)		/* empty */
#endif

#endif
