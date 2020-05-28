/*
 * Copyright (C) 2017-2020  Matheus Rodrigues <matheussr61@gmail.com>
 * Copyright (C) 2017-2019  CUJO LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef KLUA_STATES_H
#define KLUA_STATES_H

#include <lua.h>

#define KLUA_NAME_MAXSIZE 64
#define KLUA_MIN_ALLOC_BYTES (32 * 1024UL)


#define PASS

/*
KLUA_MAX_STATES_COUNT represents the total amount of states that can be created by lunatik
to obtain the total you need to calculate total = 2 ^ n where n is the value of 
KLUA_MAX_STATES_COUNT
*/
#define KLUA_MAX_STATES_COUNT 2

#define luaU_setenv(L, env, st) { \
	st **penv = (st **)lua_getextraspace(L); \
	*penv = env; }

struct klua_state {
	struct hlist_node node;
	lua_State *L;
	spinlock_t lock;
	refcount_t users;
	#ifndef PASS
	u32 dseqnum;
	#endif
	size_t maxalloc;
	size_t curralloc;
	unsigned char name[KLUA_NAME_MAXSIZE];
};

#ifndef PASS
typedef int (*klua_state_cb)(struct klua_state *s, unsigned short *total);
#endif

void klua_state_list(void);
struct klua_state *klua_state_create(size_t maxalloc, const char *name);
int klua_state_destroy(const char *name);
struct klua_state *klua_state_lookup(const char *name);
void klua_state_destroy_all(void);
bool klua_state_get(struct klua_state *s);
void klua_state_put(struct klua_state *s);
void klua_states_init(void);
void klua_states_exit(void);
void klua_execute(const char *name, const char *code);

#ifndef PASS
int klua_state_list(struct xt_lua_net *xt_lua, klua_state_cb cb,
	unsigned short *total);
#endif

#endif /* klua_stateS_H */