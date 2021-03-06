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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/idr.h>
#include <linux/ratelimit.h>
#include <linux/hashtable.h>
#include <linux/stringhash.h>

#include "lua/lualib.h"

#include "luautil.h"
#include "lunatik.h"

#ifndef LUNATIK_SETPAUSE
#define LUNATIK_SETPAUSE	(100)
#endif /* LUNATIK_SETPAUSE */

extern int luaopen_memory(lua_State *);
#ifndef LUNATIK_UNUSED
extern int luaopen_netlink(lua_State *L);
#endif /* LUNATIK_UNUSED */
extern struct lunatik_namespace *lunatik_pernet(struct net *net);

static const luaL_Reg libs[] = {
	{"memory", luaopen_memory},
#ifndef LUNATIK_UNUSED
	{"netlink", luaopen_netlink},
#endif /* LUNATIK_UNUSED */
	{NULL, NULL}
};

static inline int name_hash(void *salt, const char *name)
{
	int len = strnlen(name, LUNATIK_NAME_MAXSIZE);
	return full_name_hash(salt, name, len) & (LUNATIK_HASH_BUCKETS - 1);
}

inline lunatik_State *lunatik_statelookup(const char *name)
{
	return lunatik_netstatelookup(name, LUNATIK_DEFAULT_NS);
}

void state_destroy(lunatik_State *s)
{
	if (s == NULL) return;

	spin_lock_bh(&s->lock);
	if (s->L != NULL) {
		lua_close(s->L);
		s->L = NULL;
	}
	spin_unlock_bh(&s->lock);

	lunatik_putstate(s);
}

static void *lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	lunatik_State *s = ud;
	void *nptr = NULL;

	/* osize doesn't represent the object old size if ptr is NULL */
	osize = ptr != NULL ? osize : 0;

	if (nsize == 0) {
		s->curralloc -= osize;
		kfree(ptr);
	} else if (s->curralloc - osize + nsize > s->maxalloc) {
		pr_warn_ratelimited("maxalloc limit %zu reached on state %.*s\n",
		    s->maxalloc, LUNATIK_NAME_MAXSIZE, s->name);
	} else if ((nptr = krealloc(ptr, nsize, GFP_ATOMIC)) != NULL) {
		s->curralloc += nsize - osize;
	}

	return nptr;
}

static int state_init(lunatik_State *s)
{
	const luaL_Reg *lib;

	s->L = lua_newstate(lua_alloc, s);
	if (s->L == NULL)
		return -ENOMEM;

	luaU_setenv(s->L, s, lunatik_State);
	luaL_openlibs(s->L);

	for (lib = libs; lib->name != NULL; lib++) {
		luaL_requiref(s->L, lib->name, lib->func, 1);
		lua_pop(s->L, 1);
	}

	/* fixes an issue where the Lua's GC enters a vicious cycle.
	 * more info here: https://marc.info/?l=lua-l&m=155024035605499&w=2
	 */
	lua_gc(s->L, LUA_GCSETPAUSE, LUNATIK_SETPAUSE);

	return 0;
}

inline lunatik_State *lunatik_newstate(const char *name, size_t maxalloc)
{
	return lunatik_netnewstate(name, maxalloc, LUNATIK_DEFAULT_NS);
}

inline int lunatik_close(const char *name)
{
	return lunatik_netclosestate(name, LUNATIK_DEFAULT_NS);
}

void lunatik_closeall_from_default_ns(void)
{
	struct lunatik_namespace *lunatik_namespace;
	struct hlist_node *tmp;
	lunatik_State *s;
	int bkt;

	lunatik_namespace = lunatik_pernet(LUNATIK_DEFAULT_NS);

	spin_lock_bh(&(lunatik_namespace->statestable_lock));
	hash_for_each_safe (lunatik_namespace->states_table, bkt, tmp, s, node) {
		state_destroy(s);
	}
	spin_unlock_bh(&(lunatik_namespace->statestable_lock));
}

// TODO Is the refcount_inc_not_zero function atomic?
inline bool lunatik_getstate(lunatik_State *s)
{
	return refcount_inc_not_zero(&s->users);
}

void lunatik_putstate(lunatik_State *s)
{
	refcount_t *users = &s->users;
	spinlock_t *refcnt_lock = &(s->lunatik_namespace->rfcnt_lock);

	if (WARN_ON(s == NULL))
		return;

	if (refcount_dec_not_one(users))
		return;

	spin_lock_bh(refcnt_lock);
	if (!refcount_dec_and_test(users))
		goto unlock;

	hash_del_rcu(&s->node);
	atomic_dec(&(s->lunatik_namespace->states_count));
	kfree(s);
	s = NULL;
unlock:
	spin_unlock_bh(refcnt_lock);
	return;
}

/* DUVIDA
 * Se houver uma operação T1 que referencia um estado A e T1 estava tentando destruir
 * A quando foi interrompido por uma operação T2 que busca por este mesmo estado A para utilizá-lo
 * então T2 terá uma referência NULA? 
 * Resposta: Teoricamente o fato de estarmos trabalhando com uma tabela com RCU ativido não deixa o
 * nosso nó da tabela ser excluído enquanto houver referências para ele*/
lunatik_State *lunatik_netstatelookup(const char *name, struct net *net)
{
	lunatik_State *state;
	struct lunatik_namespace *lunatik_namespace;
	int key;

	lunatik_namespace = lunatik_pernet(net);

	key = name_hash(lunatik_namespace, name);

	hash_for_each_possible_rcu(lunatik_namespace->states_table, state, node, key) {
		if (!strncmp(state->name, name, LUNATIK_NAME_MAXSIZE))
			return state;
	}
	return NULL;
}

lunatik_State *lunatik_netnewstate(const char *name, size_t maxalloc, struct net *net)
{
	lunatik_State *s = lunatik_netstatelookup(name, net);
	struct lunatik_namespace *lunatik_namespace;
	int namelen;

	lunatik_namespace = lunatik_pernet(net);

	namelen = strnlen(name, LUNATIK_NAME_MAXSIZE);

	pr_debug("creating state: %.*s maxalloc: %zd\n", namelen, name,
		maxalloc);

	if (s != NULL) {
		pr_err("state already exists: %.*s\n", namelen, name);
		return NULL;
	}

	if (atomic_read(&(lunatik_namespace->states_count)) >= LUNATIK_HASH_BUCKETS) {
		pr_err("could not allocate id for state %.*s\n", namelen, name);
		pr_err("max states limit reached or out of memory\n");
		return NULL;
	}

	if (maxalloc < LUNATIK_MIN_ALLOC_BYTES) {
		pr_err("maxalloc %zu should be greater then MIN_ALLOC %zu\n",
		    maxalloc, LUNATIK_MIN_ALLOC_BYTES);
		return NULL;
	}

	if ((s = kzalloc(sizeof(lunatik_State), GFP_ATOMIC)) == NULL) {
		pr_err("could not allocate nflua state\n");
		return NULL;
	}

	spin_lock_init(&s->lock);
	s->maxalloc  = maxalloc;
	s->curralloc = 0;
	memcpy(&(s->name), name, namelen);

	if (state_init(s)) {
		pr_err("could not allocate a new lua state\n");
		kfree(s);
		return NULL;
	}

	spin_lock_bh(&(lunatik_namespace->statestable_lock));
	hash_add_rcu(lunatik_namespace->states_table, &(s->node), name_hash(lunatik_namespace, name));
	refcount_inc(&(s->users));
	atomic_inc(&(lunatik_namespace->states_count));
	s->lunatik_namespace = lunatik_namespace;
	s->namespace = net;
	spin_unlock_bh(&(lunatik_namespace->statestable_lock));

	pr_debug("new state created: %.*s\n", namelen, name);
	return s;
}

int lunatik_netclosestate(const char *name, struct net *net)
{
	lunatik_State *s = lunatik_netstatelookup(name, net);
	struct lunatik_namespace *lunatik_namespace;

	lunatik_namespace = lunatik_pernet(net);

	if (s == NULL || refcount_read(&s->users) > 1)
		return -1;

	spin_lock_bh(&(lunatik_namespace->statestable_lock));

	hash_del_rcu(&s->node);
	atomic_dec(&(lunatik_namespace->states_count));

	spin_lock_bh(&s->lock);
	if (s->L != NULL) {
		lua_close(s->L);
		s->L = NULL;
	}
	spin_unlock_bh(&s->lock);
	lunatik_putstate(s);

	spin_unlock_bh(&(lunatik_namespace->statestable_lock));

	return 0;
}

lunatik_State *lunatik_getenv(lua_State *L)
{
	return luaU_getenv(L, lunatik_State);
}
