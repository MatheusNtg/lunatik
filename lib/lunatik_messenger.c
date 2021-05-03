/*
 * Copyright (c) 2021 Matheus Rodrigues <matheussr61@gmail.com>
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

#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <linux/netlink.h>

#include <lauxlib.h>
#include <lua.h>
#include <lmemlib.h>

#include "../netlink_common.h"

static int pusherrmsg(lua_State *L, const char *msg)
{
	lua_pushnil(L);
	lua_pushstring(L, msg);
	return 2;
}

static int pushresponse(lua_State *L, const char *response)
{
	lua_pushboolean(L, true);
	lua_pushstring(L, response);
	return 2;
}

static int handle_kernel_msg(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nh = nlmsg_hdr(msg);
	struct genlmsghdr *gnlh = genlmsg_hdr(nh);
	struct nlattr *attrs_tb[ATTRS_COUNT + 1];
	char *kernel_msg = (char *)arg;

	if (nla_parse(attrs_tb, ATTRS_COUNT, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), NULL))
	{
		printf("Error parsing attributes\n");
		kernel_msg = NULL;
		return NL_OK;
	}

	if (attrs_tb[KERNEL_MSG]) {
		char *response = nla_get_string(attrs_tb[KERNEL_MSG]);
		memcpy(kernel_msg, response, strlen(response));
	} else {
		kernel_msg = NULL;
	}

	return NL_OK;
}

static struct nl_sock *init_socket()
{
	struct nl_sock *socket;
	if ((socket = nl_socket_alloc()) == NULL)
		return NULL;

	if (genl_connect(socket))
		return NULL;

	return socket;
}

static int send_message(lua_State *L) {
	struct nl_msg *msg;
	struct nl_sock *socket;
	int lunatik_family = -1;
	char kernel_msg[LUNATIK_FRAGMENT_SIZE];

	const char *msg_payload = luaL_checkstring(L, -1);

	if ((socket = init_socket()) == NULL) {
		return pusherrmsg(L, "Failed to initialize the socket");
	}

	if ((lunatik_family = genl_ctrl_resolve(socket, LUNATIK_FAMILY)) < 0) {
		nl_socket_free(socket);
		return pusherrmsg(L, "Failed to resolve lunatik family");
	}

	nl_socket_modify_cb(socket, NL_CB_MSG_IN, NL_CB_CUSTOM, handle_kernel_msg, kernel_msg);

	/* Prepare message */
	if ((msg = nlmsg_alloc()) == NULL) {
		nl_socket_free(socket);
		return pusherrmsg(L, "Message allocation failed");
	}

	if ((genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, lunatik_family,
					0, 0, TABLE_MSG, LUNATIK_NLVERSION)) == NULL) {
		nl_socket_free(socket);
		nlmsg_free(msg);
		return pusherrmsg(L, "Failed to put attributes on message");
	}

	NLA_PUT_STRING(msg, MSG_PAYLOAD, msg_payload);
	/* End of message preparation */

	if (nl_send_auto(socket, msg) < 0) {
		nl_socket_free(socket);
		nlmsg_free(msg);
		return pusherrmsg(L, "Failed to send message to kernel");
	}

	nl_recvmsgs_default(socket);
	nl_wait_for_ack(socket);
	
	if (kernel_msg == NULL) {
		return pusherrmsg(L, "Failed to get a message from kernel");
	}

	nl_socket_free(socket);
	nlmsg_free(msg);

	return pushresponse(L, kernel_msg);

nla_put_failure:
	nl_socket_free(socket);
	nlmsg_free(msg);
	return pusherrmsg(L, "Failed to fill message with the given payload\n");
}

static const luaL_Reg messager_lib[] = {
	{"send", send_message},
	{NULL, NULL}
};

static void setconst(lua_State *L, const char *name, lua_Integer value)
{
	lua_pushinteger(L, value);
	lua_setfield(L, -2, name);
}

int luaopen_lunatik_messenger(lua_State *L)
{
	luaL_newlib(L, messager_lib);
	
	lua_newtable(L);

	setconst(L, "CREATE_STATE", CREATE_STATE);
	setconst(L, "DO_STRING", DO_STRING);
	setconst(L, "DESTROY_STATE", DESTROY_STATE);
	setconst(L, "LIST_STATES",LIST_STATES);

	lua_setfield(L, -2, "operations");

	return 1;
}