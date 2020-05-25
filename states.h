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

struct klua_state {
	struct hlist_node node;
	lua_State *L;
	spinlock_t lock;
	refcount_t users;
	u32 dseqnum;
	size_t maxalloc;
	size_t curralloc;
	unsigned char name[NFLUA_NAME_MAXSIZE];
};

typedef int (*nflua_state_cb)(struct nflua_state *s, unsigned short *total);

struct nflua_state *klua_state_create(struct xt_lua_net *xt_lua,
        size_t maxalloc, const char *name);

int klua_state_destroy(struct xt_lua_net *xt_lua, const char *name);

struct nflua_state *klua_state_lookup(struct xt_lua_net *xt_lua,
        const char *name);

int klua_state_list(struct xt_lua_net *xt_lua, nflua_state_cb cb,
	unsigned short *total);

void klua_state_destroy_all(struct xt_lua_net *xt_lua);

bool klua_state_get(struct nflua_state *s);
void klua_state_put(struct nflua_state *s);

void klua_states_init(struct xt_lua_net *xt_lua);
void klua_states_exit(struct xt_lua_net *xt_lua);

#endif /* NFLUA_STATES_H */