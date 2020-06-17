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

#ifndef KLUA_STATES_H
#define KLUA_STATES_H

#include "lua/lua.h"

#define KLUA_NAME_MAXSIZE 64
#define KLUA_MIN_ALLOC_BYTES (32 * 1024UL)
#define KLUA_MAX_BCK_COUNT 32

struct meta_state
{
	struct hlist_head states_table[KLUA_MAX_BCK_COUNT];
	spinlock_t statestable_lock;
	spinlock_t rfcnt_lock;
	atomic_t states_count;
};

struct klua_state {
	struct hlist_node node;
	lua_State *L;
	spinlock_t lock;
	refcount_t users;
	#ifndef LUNATIK_UNUSED
	u32 dseqnum;
	#endif /*LUNATIK_UNUSED*/
	size_t maxalloc;
	size_t curralloc;
	unsigned char name[KLUA_NAME_MAXSIZE];
};

#ifndef LUNATIK_UNUSED
typedef int (*klua_state_cb)(struct klua_state *s, unsigned short *total);
#endif /*LUNATIK_UNUSED*/

void klua_state_list(void);
struct klua_state *klua_state_create(size_t maxalloc, const char *name);
int klua_state_destroy(const char *name);
struct klua_state *klua_state_lookup(const char *name);
void klua_state_destroy_all(void);
bool klua_state_get(struct klua_state *s);
void klua_state_put(struct klua_state *s);
void klua_states_init(void);
void klua_states_exit(void);

void net_state_list(struct meta_state *ms);
struct klua_state *net_state_create(struct meta_state *ms, size_t maxalloc, const char *name);
int net_state_destroy(struct meta_state *ms, const char *name);
struct klua_state *net_state_lookup(struct meta_state *ms, const char *name);
void net_state_destroy_all(struct meta_state *ms);
bool net_state_get(struct meta_state *ms, struct klua_state *s);
void net_state_put(struct meta_state *ms, struct klua_state *s);
void net_states_init(struct meta_state *ms);
void net_states_exit(struct meta_state *ms);

#ifndef LUNATIK_UNUSED
int klua_state_list(struct xt_lua_net *xt_lua, klua_state_cb cb,
	unsigned short *total);
#endif /*LUNATIK_UNUSED*/

#endif /* klua_stateS_H */
