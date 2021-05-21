/*
 * Copyright (C) 2020  Matheus Rodrigues <matheussr61@gmail.com>
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

#include <lmemlib.h>

#include "luautil.h"
#include "lunatik.h"
#include "netlink_common.h"

#define DATA_RECV_FUNC	("receive_callback")
#define MAX_INSTRUCTIONS	(100)

struct lunatik_nl_state {
	char name[LUNATIK_NAME_MAXSIZE];
	size_t maxalloc;
	size_t curralloc;
};

extern struct lunatik_namespace *lunatik_pernet(struct net *net);

static int lunatikN_handletablemsg(struct sk_buff *buff, struct genl_info *info);

struct nla_policy lunatik_policy[ATTRS_COUNT] = {
	[USER_SPACE_MSG] = { .type = NLA_STRING },
	[KERNEL_MSG]	 = { .type = NLA_STRING }
};

static const struct genl_ops l_ops[] = {
	{
		.cmd    = TABLE_MSG,
		.doit   = lunatikN_handletablemsg,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = lunatik_policy
#endif
	}
};

struct genl_family lunatik_family = {
	.name 	 = LUNATIK_FAMILY,
	.version = LUNATIK_NLVERSION,
	.maxattr = ATTRS_MAX,
	.netnsok = true,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
	.policy  = lunatik_policy,
#endif
	.module  = THIS_MODULE,
	.ops     = l_ops,
	.n_ops   = ARRAY_SIZE(l_ops),
	.parallel_ops = false,
};

static int send_msg_to_userspace(char *msg, struct genl_info *info)
{
	struct sk_buff *obuff;
	void *msg_head;
	
	if (msg == NULL) {
		pr_err("Message can't be null\n");
	}

	if ((obuff = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL)) == NULL) {
		pr_err("Failed allocating message to an reply\n");
		return -1;
	}

	if ((msg_head = genlmsg_put_reply(obuff, info, &lunatik_family, 0, GET_CURRALLOC)) == NULL) {
		pr_err("Failed to put generic netlink header\n");
		return -1;
	}

	if (nla_put_string(obuff, KERNEL_MSG, msg)) {
		pr_err("Failed to put attributes on socket buffer\n");
		return -1;
	}

	genlmsg_end(obuff, msg_head);

	if (genlmsg_reply(obuff, info) < 0) {
		pr_err("Failed to send message to user space\n");
		return -1;
	}

	pr_debug("Message sent to user space\n");
	return 0;
}

static void lstop(struct lua_State *L, struct lua_Debug *ar) {
	luaL_error(L, "instruction limit exceeded");
}

static void create_error_msg(char *buffer, char *msg)
{
	if (buffer != NULL) {
		sprintf(buffer, "{"
						" response = \"%s\","
						" operation_success = false"
						" }", msg);
	}
}

static int run_safe_code_on_control_state(struct lunatik_controlstate *control_state, char *code)
{
	lua_State *L = control_state->lua_state;
	
	if (L == NULL) return -1;

	if (luaL_loadstring(L, code) != LUA_OK) return -1;

	lua_sethook(L, lstop, LUA_MASKCOUNT, MAX_INSTRUCTIONS);

	if (lua_pcall(L, 0, LUA_MULTRET, 0)) {
		pr_err(KERN_INFO "Error executing code on control state");
		return -1;
	}

	return 0;
}

static int get_int_from_table(struct lunatik_controlstate *control_state, char *attr_name, lua_Integer *integer) 
{
	lua_State *L = control_state->lua_state;

	if (L == NULL) return -EPERM;

	/* First get the global table named msg */
	if(lua_getglobal(L, "msg") != LUA_TTABLE) {
		return -EINVAL;
	}

	if(lua_getfield (L, -1, attr_name) != LUA_INT_TYPE) {
		return -EINVAL;
	}

	*integer = lua_tointeger(L, -1);

	return 0;
}

static int get_string_from_table(struct lunatik_controlstate *control_state, char *attr_name, char *string) 
{
	lua_State *L = control_state->lua_state;
	const char *tmp_string;

	if (L == NULL || string == NULL) return -EPERM;

	/* First get the global table named msg */
	if(lua_getglobal(L, "msg") != LUA_TTABLE) {
		return -EINVAL;
	}

	if(lua_getfield(L, -1, attr_name) != LUA_TSTRING) {
		return -EINVAL;
	}

	tmp_string = lua_tostring(L, -1);
	memcpy(string, tmp_string, strlen(tmp_string));

	return 0;
}

static int get_bool_from_table(struct lunatik_controlstate *controlstate, char *attr_name, bool *boolean)
{
	lua_State *L = controlstate->lua_state;

	if (L == NULL) return -EPERM;

	/* First get the global table named msg */
	if(lua_getglobal(L, "msg") != LUA_TTABLE) {
		return -EINVAL;
	}

	if(lua_getfield(L, -1, attr_name) != LUA_TBOOLEAN) {
		return -EINVAL;
	}

	*boolean = lua_toboolean(L, -1);

	return 0;
}

static char *create_string(size_t len)
{
	char *result;

	result = kzalloc(len, GFP_KERNEL);

	return result;
}

static int handle_create_state_msg(struct lunatik_controlstate *control_state, char *response, struct net *net)
{
	char *state_name;
	lua_Integer max_alloc;
	lua_State *L = control_state->lua_state;
	lunatik_State *state;

	if (L == NULL) {
		create_error_msg(response, "Lua control state is not allocated");
		return -ENODATA;
	}

	state_name = create_string(LUNATIK_NAME_MAXSIZE);

	if (state_name == NULL) {
		create_error_msg(response, "Failed to allocate memory for state name");
		return -ENOMEM;
	}

	if (
		get_string_from_table(control_state, "name", state_name) ||
		get_int_from_table(control_state, "maxalloc", &max_alloc)
	) {
		create_error_msg(response, "Failed to get state informations");
		kfree(state_name);
		state_name = NULL;
		return -EPROTO;
	}

	state = lunatik_netnewstate(state_name, max_alloc, net);

	if (state == NULL) {
		create_error_msg(response, "Failed to create state");
		kfree(state_name);
		state_name = NULL;
		return -EPROTO;
	}

	sprintf(response, "{ response = 'State %s successfully created', curr_alloc = %lu, operation_success = true }", 
								  state_name, state->curralloc);
	kfree(state_name);
	state_name = NULL;

	return 0;
}

/*
!TODO 
!1. Review errors
!2. Return to user if the code was or not succesfully executed
*/
static int handle_do_string(struct lunatik_controlstate *controlstate, char *response, struct net *net)
{
	char *state_name;
	char *code;
	lua_State *L;
	lunatik_State *lunatik_state;

	L = controlstate->lua_state;

	if (L == NULL) {
		create_error_msg(response, "Failed to get control state");
		return -EPROTO;
	}

	state_name = create_string(LUNATIK_NAME_MAXSIZE);
	code = create_string(LUNATIK_FRAGMENT_SIZE);

	if (state_name == NULL || code == NULL) {
		create_error_msg(response, "Failed to create buffers on kernel");
		return -EPROTO;
	}

	if (
		get_string_from_table(controlstate, "name", state_name) ||
		get_string_from_table(controlstate, "code", code)
	) {
		create_error_msg(response, "Failed to get informations from table");
		return -EPROTO;
	}

	lunatik_state = lunatik_netstatelookup(state_name, net);

	if (lunatik_state == NULL) {
		create_error_msg(response, "Failed to find the requested state");
		return -EPROTO;
	}
	
	if (luaL_dostring(lunatik_state->L, code)) {
		create_error_msg(response, "Failed to load the requested code");
	}

	sprintf(response, "{ response = 'Code successfully loaded', operation_success = true }");

	return 0;
}

// TODO put consistent errors
static int handle_put_state(struct lunatik_controlstate *controlstate, char *response, struct net* namespace)
{
	char *state_name;
	lunatik_State *lunatik_state;

	state_name = create_string(LUNATIK_NAME_MAXSIZE);

	if (state_name == NULL) {
		create_error_msg(response, "Failed to allocate memory to state name buffer");
		return -1;
	}

	if (
		get_string_from_table(controlstate, "name", state_name)
	) {
		create_error_msg(response, "Failed to get attributes from lua table");
		return -1;
	}

	lunatik_state = lunatik_netstatelookup(state_name, namespace);

	if (lunatik_state == NULL) {
		create_error_msg(response, "Lunatik state not found");
		return -1;
	}

	lunatik_putstate(lunatik_state);

	sprintf(response, "{ response = 'Successfully put state', operation_success = true }");

	return 0;
}

// TODO make error proper error handling
static int handle_list_states(struct lunatik_controlstate *controlstate, char *response, struct net *namespace)
{
	struct lunatik_namespace *lunatik_namespace;
	struct lunatik_us_state *states;
	bool is_init;
	size_t number_of_states;
	int bkt;
	int index;
	lunatik_State *state;
	lua_Integer curr_state;

	is_init = false;
	number_of_states = 0;
	index = 0;
	lunatik_namespace = lunatik_pernet(namespace);

	if (lunatik_namespace == NULL) {
		create_error_msg(response, "Failed to get namespace");
		return -1;
	}

	number_of_states = atomic_read(&lunatik_namespace->states_count);

	if (get_bool_from_table(controlstate, "init", &is_init)) {
		create_error_msg(response, "Failed to get init atribute");
		return -1;
	}

	if (is_init) {
		lunatik_namespace->states_list = kmalloc(sizeof(struct lunatik_us_state) * number_of_states, GFP_KERNEL);
		states = lunatik_namespace->states_list;
		
		if (states == NULL) {
			create_error_msg(response, "Failed to create buffer to send states information");
			return -1;
		}
		
		hash_for_each(lunatik_namespace->states_table, bkt, state, node) {
			states[index].name = state->name;
			states[index].curralloc = state->curralloc;
			states[index].maxalloc = state->maxalloc;
			index++;

		}
		
		sprintf(response, "{ response = 'Operation successfully initialized', operation_success = true, states_amount = %lu }", number_of_states);
		
		return 0;
	}

	if (
		get_int_from_table(controlstate, "curr_state_to_get", &curr_state)
	) {
		create_error_msg(response, "Failed to get information about the current requested element");
		return -1;
	}

	if (curr_state >= number_of_states) {
		create_error_msg(response, "Trying to get a state that does not exists");
		return -1;
	}

	states = lunatik_namespace->states_list;

	sprintf(response, 
			" { response = { state_name = '%s', curralloc = %lu, maxalloc = %lu }, operation_success = true } ",
			states[curr_state].name, states[curr_state].curralloc, states[curr_state].maxalloc);

	return 0;
}

// TODO Handle errors
static int handle_get_state(struct lunatik_controlstate *controlstate, char *response, struct net *namespace)
{
	lunatik_State *state;
	char *state_name;

	state_name = create_string(LUNATIK_NAME_MAXSIZE);

	if (state_name == NULL) {
		create_error_msg(response, "Failed to alocate memory to search for a state name");
		return -1;
	}

	if (
		get_string_from_table(controlstate, "state_name", state_name)
	) {
		create_error_msg(response, "Failed to get attribute name from table");
		return -1;
	}

	state = lunatik_netstatelookup(state_name, namespace);

	if (state == NULL) {
		create_error_msg(response, "State not found");
		return -1;
	}

	sprintf(response, "{ state_name = '%s', curr_alloc = %ld, max_alloc = %ld, operation_success = true } ", state->name, state->curralloc, state->maxalloc);

	return 0;
}

static int lunatikN_handletablemsg(struct sk_buff *buff, struct genl_info *info)
{
	pr_debug("Receive a msg from user space\n");

	struct lunatik_controlstate *control_state;
	char response_msg[LUNATIK_FRAGMENT_SIZE];
	char *msg_payload;
	lua_Integer op_number;

	control_state = &lunatik_pernet(genl_info_net(info))->control_state;
	msg_payload = (char *)nla_data(info->attrs[USER_SPACE_MSG]);

	op_number = 0;

	if (run_safe_code_on_control_state(control_state, msg_payload)) {
		send_msg_to_userspace("{ response = 'Failed to load the table on kernel', operation_success = false }", info);
		return 0;
	}

	if (get_int_from_table(control_state, "operation", &op_number)) {
		send_msg_to_userspace("{ response = 'Failed to get operation on the received table', operation_success = false }", info);
		return 0;
	}

	switch (op_number)
	{
	case CREATE_STATE:
		handle_create_state_msg(control_state, response_msg, genl_info_net(info));
		break;
	case DO_STRING:
		handle_do_string(control_state, response_msg, genl_info_net(info));
		break;
	case PUT_STATE:
		handle_put_state(control_state, response_msg, genl_info_net(info));
		break;
	case LIST_STATES:
		handle_list_states(control_state, response_msg, genl_info_net(info));
		break;
	case GET_STATE:
		handle_get_state(control_state, response_msg, genl_info_net(info));
		break;
	default:
		break;
	}

	send_msg_to_userspace(response_msg, info);

	return 0;
error:
	// TODO Implement this
	return 0;
}


/* Note: Most of the function below is copied from NFLua: https://github.com/cujoai/nflua
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

static int handle_data(lua_State *L)
{
	int error;
	struct lunatik_data *req = lua_touserdata(L, 1);

	lua_pop(L, 1);

	luamem_newref(L);
	if (!luamem_setref(L, -1, req->buffer, req->size, NULL))
		return luaL_error(L, "There is no memory on this position of the lua stack\n");

	if (lua_getglobal(L, DATA_RECV_FUNC) != LUA_TFUNCTION)
		return luaL_error(L, "couldn't find receive function: %s\n",
				DATA_RECV_FUNC);

	lua_pushvalue(L, 1); /* memory */

	error = lua_pcall(L, 1, 0, 0);

	luamem_setref(L, 1, NULL, 0, NULL);

	if (error)
		lua_error(L);

	return 0;
}
