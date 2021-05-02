/*
 * Copyright (C) 2020  Matheus Rodrigues <matheussr61@gmail.com>
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

#ifndef LUNATIK_STATES_H
#define LUNATIK_STATES_H

#include <linux/hashtable.h>

#include "lua/lua.h"
#include "lunatik_conf.h"
#include "netlink.h"
#include "luautil.h"

struct lunatik_controlstate {
	lua_State *lua_state;
	size_t max_alloc;
	size_t curr_alloc;
};

struct lunatik_namespace {
	DECLARE_HASHTABLE(states_table, ilog2(LUNATIK_HASH_BUCKETS));
	struct reply_buffer reply_buffer;
	struct lunatik_controlstate control_state;
	spinlock_t statestable_lock;
	spinlock_t rfcnt_lock;
	spinlock_t sendmessage_lock;
	atomic_t states_count;
};

typedef struct lunatik_state {
	struct hlist_node node;
	struct lunatik_namespace *lunatik_namespace;
	struct genl_info usr_state_info;
	struct lunatik_data data;
	struct net *namespace;
	lua_State *L;
	char *code_buffer;
	int buffer_offset;
	spinlock_t lock;
	refcount_t users;
	size_t maxalloc;
	size_t curralloc;
	size_t scriptsize;
	bool inuse;
	unsigned char name[LUNATIK_NAME_MAXSIZE];
} lunatik_State;

static inline struct net *lunatik_get_namespace(lunatik_State *state)
{
	return state->namespace;
}

lunatik_State *lunatik_newstate(const char *name, size_t maxalloc);
int lunatik_close(const char *name);
lunatik_State *lunatik_statelookup(const char *name);

bool lunatik_getstate(lunatik_State *s);
void lunatik_putstate(lunatik_State *s);

lunatik_State *lunatik_netnewstate(const char *name, size_t maxalloc, struct net *net);
int lunatik_netclosestate(const char *name, struct net *net);
lunatik_State *lunatik_netstatelookup(const char *name, struct net *net);

lunatik_State *lunatik_getenv(lua_State *L);

#endif /* LUNATIK_STATES_H */
