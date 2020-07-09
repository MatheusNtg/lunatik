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
#define KLUA_HASH_BUCKETS 32
#define KLUA_MIN_ALLOC_BYTES (32 * 1024UL)

typedef enum {
	FREE,
	RECEIVING,
} klua_state_status;

struct klua_communication {
	struct hlist_head states_table [KLUA_HASH_BUCKETS];
	struct hlist_head clients_table [KLUA_HASH_BUCKETS];
	spinlock_t client_lock;
	spinlock_t statestable_lock;
	spinlock_t rfcnt_lock;
	atomic_t states_count;
};

struct klua_state {
	struct hlist_node node;
	lua_State *L;
	char *buffer;
	int offset;
	klua_state_status status;
	size_t curr_script_size;
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

void net_state_list(struct klua_communication *klc);
struct klua_state *net_state_create(struct klua_communication *klc, size_t maxalloc, const char *name);
int net_state_destroy(struct klua_communication *klc, const char *name);
struct klua_state *net_state_lookup(struct klua_communication *klc, const char *name);
void net_state_destroy_all(struct klua_communication *klc);
bool net_state_get(struct klua_communication *klc, struct klua_state *s);
void net_state_put(struct klua_communication *klc, struct klua_state *s);
void net_states_init(struct klua_communication *klc);
void net_states_exit(struct klua_communication *klc);

#ifndef LUNATIK_UNUSED
int klua_state_list(struct klua_communication *klc, klua_state_cb cb,
	unsigned short *total);
#endif /*LUNATIK_UNUSED*/

#endif /* klua_stateS_H */
