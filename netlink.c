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
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/netlink.h>
#include <net/sock.h>

#include "luautil.h"
#include "states.h"
#include "netlink_common.h"

extern struct klua_communication *klua_pernet(struct net *net);

static int klua_create_state(struct sk_buff *buff, struct genl_info *info);

struct nla_policy lunatik_policy[ATTRS_COUNT] = {
	[STATE_NAME] = { .type = NLA_STRING },
	[MAX_ALLOC]  = { .type = NLA_U32 },
};

static const struct genl_ops l_ops[] = {
	{
		.cmd    = CREATE_STATE,
		.doit   = klua_create_state,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		/*Before kernel 5.2.0, each operation has its own policy*/
		.policy = lunatik_policy
#endif
	},
};

struct genl_family lunatik_family = {
	.name 	 = LUNATIK_FAMILY,
	.version = NKLUA_VERSION,
	.maxattr = ATTRS_MAX,
	.netnsok = true, /*Make this family visible for all namespaces*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
	.policy  = lunatik_policy,
#endif
	.module  = THIS_MODULE,
	.ops     = l_ops,
	.n_ops   = ARRAY_SIZE(l_ops),
};

struct klua_client {
	struct hlist_node node;
	struct mutex lock;
	u32 pid;
	u32 seq;
	u16 msgtype;
};

static u32 hash_random __read_mostly;

#define pid_hash(pid) (jhash_1word(pid, hash_random) & (KLUA_HASH_BUCKETS - 1))

static struct klua_client *client_lookup(struct klua_communication *klc, u32 pid)
{
	struct klua_client *client;

	if (unlikely(klc == NULL))
		return NULL;

	hash_for_each_possible_rcu(klc->clients_table, client, node, pid_hash(pid)){
		if (client->pid == pid)
			return client;
	}
	return NULL;
}

static struct klua_client *client_create(struct klua_communication *klc, u32 pid)
{
	struct klua_client *client;

	if (unlikely(klc == NULL))
		return NULL;

	if ((client = kzalloc(sizeof(struct klua_client), GFP_ATOMIC)) == NULL)
		return NULL;

	mutex_init(&client->lock);
	client->pid = pid;
	hash_add_rcu(klc->clients_table, &client->node, pid_hash(pid));

	return client;
}

static inline struct klua_client *client_find_or_create(
		struct klua_communication *klc, u32 pid)
{
	struct klua_client *client = client_lookup(klc, pid);
	if (client == NULL)
		client = client_create(klc, pid);
	return client;
}
// TODO Arrumar essa função
#ifndef LUNATIK_UNUSED
static void client_destroy(struct klua_communication *klc, u32 pid)
{
	struct klua_client *client = client_lookup(klc, pid);

	if (unlikely(client == NULL))
		return;

	hlist_del_rcu(&client->node);

	mutex_lock(&client->lock);
	if (client->request.release && client->request.buffer != NULL)
		kfree(client->request.buffer);
	mutex_unlock(&client->lock);

	kfree(client);
}
#endif

static int klua_create_state(struct sk_buff *buff, struct genl_info *info)
{
	struct klua_communication *klc;
	struct klua_client *client;
	char *state_name;
	u32 *max_alloc;
	u32 pid;

	pr_debug("Received a CREATE_STATE message\n");
	
	klc = klua_pernet(genl_info_net(info));
	state_name = (char *)nla_data(info->attrs[STATE_NAME]);
	max_alloc = (u32 *)nla_data(info->attrs[MAX_ALLOC]);
	pid = info->snd_portid;

	if ((client = client_find_or_create(klc, pid)) == NULL) {
		pr_err("Failed to create an client while try to create an state\n");
		return 0;
	}

	mutex_lock(&client->lock);
	net_state_create(klc, *max_alloc, state_name);
	mutex_unlock(&client->lock);

	return 0;
}








