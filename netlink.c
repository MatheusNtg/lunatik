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
static int klua_execute_code(struct sk_buff *buff, struct genl_info *info);
static int klua_destroy_state(struct sk_buff *buff, struct genl_info *info);

struct nla_policy lunatik_policy[ATTRS_COUNT] = {
	[STATE_NAME] = { .type = NLA_STRING },
	[MAX_ALLOC]  = { .type = NLA_U32 },
	[CODE]		 = { .type = NLA_STRING },
	[FLAGS] 	 = { .type = NLA_U8 },
	[SCRIPT_SIZE]= { .type = NLA_U32 }, //TODO Ver se eu preciso realmente desse tamanho, e decidir qual vai ser o tamanho máximo (de arquivo) suportado pela API
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
	{
		.cmd    = EXECUTE_CODE,
		.doit   = klua_execute_code,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		/*Before kernel 5.2.0, each operation has its own policy*/
		.policy = lunatik_policy
#endif
	},
	{
		.cmd    = DESTROY_STATE,
		.doit   = klua_destroy_state,
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

static int klua_create_state(struct sk_buff *buff, struct genl_info *info)
{
	struct klua_communication *klc;
	char *state_name;
	u32 *max_alloc;
	u32 pid;

	pr_debug("Received a CREATE_STATE message\n");
	
	klc = klua_pernet(genl_info_net(info));
	state_name = (char *)nla_data(info->attrs[STATE_NAME]);
	max_alloc = (u32 *)nla_data(info->attrs[MAX_ALLOC]);
	pid = info->snd_portid;

	net_state_create(klc, *max_alloc, state_name);

	return 0;
}

static int klua_execute_code(struct sk_buff *buff, struct genl_info *info)
{
	struct klua_state *s;
	struct klua_communication *klc;
	const char *finalscript;
	char *fragment;
	char *state_name;
	u8 flags;

	pr_debug("Received a EXECUTE_CODE message\n");

	klc = klua_pernet(genl_info_net(info));
	state_name = (char *)nla_data(info->attrs[STATE_NAME]);
	fragment = (char *)nla_data(info->attrs[CODE]);
	flags = *((u8*)nla_data(info->attrs[FLAGS]));

	if ((s = net_state_lookup(klc, state_name)) == NULL) {
		pr_err("Error finding klua state\n");
		return 0;
	}

	if ((flags & KLUA_INIT) && (s->status == FREE)) {
		s->curr_script_size = *((u32*)nla_data(info->attrs[SCRIPT_SIZE]));
		s->status = RECEIVING;
		
		if ((s->buffer = kmalloc(sizeof(luaL_Buffer), GFP_KERNEL)) == NULL) {
			pr_err("Failed allocating memory to code buffer\n");
			return 0;
		}

		luaL_buffinit(s->L, s->buffer);	
	} // TODO Otherwise, reply with a "busy state"

	if ((flags & KLUA_MULTIPART_MSG) && (s->status == RECEIVING)) {
		luaL_addlstring(s->buffer, fragment, KLUA_MAX_SCRIPT_SIZE);
	}


	if ((flags & KLUA_LAST_MSG) && (s->status == RECEIVING)){
		pr_info("Recebi a última mensagem\n");
	
		luaL_addstring(s->buffer, fragment);
		luaL_pushresult(s->buffer);

		finalscript = lua_tostring(s->L, -1); // TODO How to free this memory?
		
		if (!klua_state_get(s)) {
			pr_err("Failed to get state\n");
			return 0;
		}

		luaL_dostring(s->L, finalscript);
		//luaL_loadbufferx(s->L, finalscript, s->curr_script_size, "teste", "t");
		//lua_pcall(s->L, 0, 0, 0);
		s->status = FREE;	
		kfree(s->buffer);
		klua_state_put(s);
		
	}
	

	return 0;
}

static int klua_destroy_state(struct sk_buff *buff, struct genl_info *info)
{
	struct klua_communication *klc;
	char *state_name;
	
	klc = klua_pernet(genl_info_net(info));
	state_name = (char *)nla_data(info->attrs[STATE_NAME]);
	
	pr_debug("Received a DESTROY_STATE command\n");

	if (net_state_destroy(klc, state_name)) {
		pr_err("Failed to destroy state %s\n", state_name);
		return 0;
	}	

	return 0;
}




