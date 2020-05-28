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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/idr.h>
#include <linux/ratelimit.h>
#include <linux/hashtable.h>

#include <lualib.h>
#include <lauxlib.h>

#include "states.h"

#ifndef KLUA_SETPAUSE
#define KLUA_SETPAUSE	100
#endif /* KLUA_SETPAUSE */


DEFINE_HASHTABLE(states_table, KLUA_MAX_STATES_COUNT);
spinlock_t gstorage_lock; // This is the locked used to lock operations on the global hash table
spinlock_t rfcnt_lock;
atomic_t states_count;

static int name_hash(const char *name)
{
	int key = 0;
    char temp;
    while((temp = *name++)){
        key += temp;
    }

    return key;
}

static bool refcount_dec_and_lock_bh(refcount_t *r, spinlock_t *lock)
{
	if (refcount_dec_not_one(r))
		return false;

	spin_lock_bh(lock);
	if (!refcount_dec_and_test(r)) {
		spin_unlock_bh(lock);
		return false;
	}
	return true;
}

struct klua_state *klua_state_lookup(const char *name)
{
	struct klua_state *state;
	int key;

	key = name_hash(name);

	hash_for_each_possible_rcu(states_table, state, node, key) {
		if (!strncmp(state->name, name, KLUA_NAME_MAXSIZE))
			return state;
	}
	return NULL;
}

static void state_destroy(struct klua_state *s)
{
	hash_del_rcu(&s->node);
	atomic_dec(&states_count);

	spin_lock_bh(&s->lock);
	if (s->L != NULL) {
		lua_close(s->L);
		s->L = NULL;
	}
	spin_unlock_bh(&s->lock);
	klua_state_put(s);
}

static void *lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	struct klua_state *s = ud;
	void *nptr = NULL;

	/* osize doesn't represent the object old size if ptr is NULL */
	osize = ptr != NULL ? osize : 0;

	if (nsize == 0) {
		s->curralloc -= osize;
		kfree(ptr);
	} else if (s->curralloc - osize + nsize > s->maxalloc) {
		pr_warn_ratelimited("maxalloc limit %zu reached on state %.*s\n",
		    s->maxalloc, KLUA_NAME_MAXSIZE, s->name);
	} else if ((nptr = krealloc(ptr, nsize, GFP_ATOMIC)) != NULL) {
		s->curralloc += nsize - osize;
	}

	return nptr;
}

static int state_init(struct klua_state *s)
{
	
	s->L = lua_newstate(lua_alloc, s);
	if (s->L == NULL)
		return -ENOMEM;

	luaU_setenv(s->L, s, struct klua_state);
	luaL_openlibs(s->L);

	/* fixes an issue where the Lua's GC enters a vicious cycle.
	 * more info here: https://marc.info/?l=lua-l&m=155024035605499&w=2
	 */
	lua_gc(s->L, LUA_GCSETPAUSE, KLUA_SETPAUSE);

	return 0;
}

struct klua_state *klua_state_create(size_t maxalloc, const char *name)
{
	struct klua_state *s = klua_state_lookup(name);
	int namelen = strnlen(name, KLUA_NAME_MAXSIZE);

	pr_debug("creating state: %.*s maxalloc: %zd\n", namelen, name,
		maxalloc);

	if (s != NULL) {
		pr_err("state already exists: %.*s\n", namelen, name);
		return NULL;
	}

	if (atomic_read(&states_count) >= (1 << KLUA_MAX_STATES_COUNT)) {
		pr_err("could not allocate id for state %.*s\n", namelen, name);
		pr_err("max states limit reached or out of memory\n");
		return NULL;
	}

	if (maxalloc < KLUA_MIN_ALLOC_BYTES) {
		pr_err("maxalloc %zu should be greater then MIN_ALLOC %zu\n",
		    maxalloc, KLUA_MIN_ALLOC_BYTES);
		return NULL;
	}

	if ((s = kzalloc(sizeof(struct klua_state), GFP_ATOMIC)) == NULL) {
		pr_err("could not allocate nflua state\n");
		return NULL;
	}

	spin_lock_init(&s->lock);
	s->dseqnum   = 0;
	s->maxalloc  = maxalloc;
	s->curralloc = 0;
	memcpy(&(s->name), name, namelen);

	if (state_init(s)) {
		pr_err("could not allocate a new lua state\n");
		kfree(s);
		return NULL;
	}
	
	spin_lock_bh(&gstorage_lock);
	hash_add_rcu(states_table, &(s->node), name_hash(name));
	refcount_inc(&(s->users));
	atomic_inc(&(states_count));
	spin_unlock_bh(&gstorage_lock);
	
	pr_debug("new state created: %.*s\n", namelen, name);
	return s;
}

int klua_state_destroy(const char *name)
{
	struct klua_state *s = klua_state_lookup(name);

	if (s == NULL || refcount_read(&s->users) > 1)
		return -1;

	spin_lock_bh(&gstorage_lock);
	state_destroy(s);
	spin_unlock_bh(&gstorage_lock);
	
	return 0;
}

#ifndef PASS
int klua_state_list(struct xt_lua_net *xt_lua, klua_state_cb cb,
	unsigned short *total)
{
	struct hlist_head *head;
	struct klua_state *s;
	int i, ret = 0;

	spin_lock_bh(&xt_lua->state_lock);

	*total = atomic_read(&xt_lua->state_count);

	for (i = 0; i < XT_LUA_HASH_BUCKETS; i++) {
		head = &xt_lua->state_table[i];
		kpi_hlist_for_each_entry_rcu(s, head, node) {
			if ((ret = cb(s, total)) != 0)
				goto out;
		}
	}

out:
	spin_unlock_bh(&xt_lua->state_lock);
	return ret;
}
#endif

void klua_state_list()
{
	int bkt;
	struct klua_state *state;

	if(hash_empty(states_table))
		return;

	hash_for_each_rcu(states_table, bkt, state, node){
		printk("State %s, curralloc %ld, maxalloc %ld\n", state->name, state->curralloc, state->maxalloc);
	}
}

void klua_state_destroy_all()
{
	struct klua_state *s;
	struct hlist_node *tmp;
	int bkt;

	spin_lock_bh(&gstorage_lock);

	hash_for_each_safe(states_table,bkt,tmp,s,node) {
		state_destroy(s);
	}

	spin_unlock_bh(&gstorage_lock);
	
}

bool klua_state_get(struct klua_state *s)
{
	return refcount_inc_not_zero(&(s->users));
}

void klua_state_put(struct klua_state *s)
{

	if (WARN_ON(s == NULL))
		return;

	if (refcount_dec_and_lock_bh(&(s->users), &rfcnt_lock)) {
		kfree(s);
		spin_unlock_bh(&rfcnt_lock);
	}
}

void klua_states_init()
{
	atomic_set(&states_count, 0);
	spin_lock_init(&gstorage_lock);
	spin_lock_init(&rfcnt_lock);
	hash_init(states_table);
}

void klua_states_exit()
{
	klua_state_destroy_all();
}

void klua_execute(const char *name, const char *code)
{
	struct klua_state *state;
	state = klua_state_lookup(name);
	if(name == NULL || code == NULL || state == NULL)
		return;

	luaL_dostring(state->L, code);
}