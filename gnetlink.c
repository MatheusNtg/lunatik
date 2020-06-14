/*
* Copyright (C) 2020  Matheus Rodrigues <matheussr61@gmail.com>
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "gnetlink.h"
#include "states.h"

struct nla_policy const l_policy[ATTR_COUNT] = {
	[STATE_NAME] = {.type = NLA_STRING},
	[MAX_ALLOC]  = {.type = NLA_U64},
	[EXEC_CODE]  = {.type = NLA_STRING},
};

static int netlink_create_state(struct sk_buff *buff, struct genl_info *info);
static int list_states_wrapper(struct sk_buff *buff, struct genl_info *info);
static int execute_lua_code(struct sk_buff *buff, struct genl_info *info);
static int delete_state_wrapper(struct sk_buff *buff, struct genl_info *info);
static int destroy_all_states_wrapper(struct sk_buff *buff, struct genl_info *info);

static const struct genl_ops l_ops[] = {
	{
		.cmd    = CREATE_STATE,
		.doit   = netlink_create_state,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		/*Before kernel 5.2.0, each operation has its own policy*/
		.policy = l_policy
#endif
	},
	{
		.cmd    = LIST_STATES,
		.doit   = list_states_wrapper,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = l_policy
#endif
	},
	{
		.cmd    = EXECUTE_CODE,
		.doit   = execute_lua_code,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = l_policy
#endif
	},
	{
		.cmd    = DELETE_STATE,
		.doit   = delete_state_wrapper,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = l_policy
#endif
	},
	{
		.cmd    = DESTROY_ALL_STATES,
		.doit   = destroy_all_states_wrapper,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		/*Before kernel 5.2.0, each operation has its own policy*/
		.policy = l_policy
#endif
	}

};

struct genl_family lunatik_family = {
	.name 	 = LUNATIK_FAMILY,
	.version = 1,
	.maxattr = ATTR_MAX,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
	.policy  = l_policy,
#endif
	.module  = THIS_MODULE,
	.ops     = l_ops,
	.n_ops   = ARRAY_SIZE(l_ops),
};

static int netlink_create_state(struct sk_buff *buff, struct genl_info *info)
{	
    unsigned char *name = (unsigned char *)nla_data(info->attrs[STATE_NAME]);
    unsigned long max_alloc = *((unsigned long*) nla_data(info->attrs[MAX_ALLOC]));
    
    klua_states_init();
    
    if (klua_state_create(max_alloc, name) == NULL)
        return -1;
	
    return 0;
}


static int list_states_wrapper(struct sk_buff *buff, struct genl_info *info)
{
	klua_state_list();
	return 1;
}

static int execute_lua_code(struct sk_buff *buff, struct genl_info *info)
{
	char * state_name = (unsigned char *) nla_data(info->attrs[STATE_NAME]);
	unsigned char * code =(unsigned char *) nla_data(info->attrs[EXEC_CODE]);
	struct klua_state *s = klua_state_lookup(state_name);

	if (s == NULL)
		return -1;

	pr_info("[DEBUG] %s -> Code: %s\n", __func__, code);

	klua_execute(state_name, code);
	return 0;
}

static int delete_state_wrapper(struct sk_buff *buff, struct genl_info *info)
{
	const unsigned char *name = (unsigned char *)nla_data(info->attrs[STATE_NAME]);

	if (klua_state_destroy(name))
		return -1;

	return 0;
}


static int destroy_all_states_wrapper(struct sk_buff *buff, struct genl_info *info)
{
	klua_state_destroy_all();
	return 0;
}