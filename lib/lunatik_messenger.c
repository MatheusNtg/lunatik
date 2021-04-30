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

static int __pusherrmsg(lua_State *L, const char *msg)
{
	lua_pushnil(L);
	lua_pushstring(L, msg);
	return 2;
}

static struct nl_sock *__init_socket()
{
	struct nl_sock *socket;
	if ((socket = nl_socket_alloc()) == NULL)
		return NULL;

	if (genl_connect(socket))
		return NULL;

	if ((genl_ctrl_resolve(socket, LUNATIK_FAMILY)) < 0)
		return NULL;

	return socket;
}

static int send_message(lua_State *L) {
	struct nl_msg *msg;
	struct nl_sock *socket;
	int lunatik_family = -1;

	const char *msg_payload = luaL_checkstring(L, -1);

	if ((socket = __init_socket()) == NULL) {
		return __pusherrmsg(L, "Failed to initialize the socket");
	}

	if ((lunatik_family = genl_ctrl_resolve(socket, LUNATIK_FAMILY)) < 0) {
		nl_socket_free(socket);
		return __pusherrmsg(L, "Failed to resolve lunatik family");
	}

	/* Prepare message */
	if ((msg = nlmsg_alloc()) == NULL) {
		nl_socket_free(socket);
		return __pusherrmsg(L, "Message allocation failed");
	}

	if ((genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, lunatik_family,
					0, 0, TABLE_MSG, LUNATIK_NLVERSION)) == NULL) {
		nl_socket_free(socket);
		nlmsg_free(msg);
		return __pusherrmsg(L, "Failed to put attributes on message");
	}

	NLA_PUT_STRING(msg, MSG_PAYLOAD, msg_payload);
	/* End of message preparation */

	if (nl_send_auto(socket, msg) < 0) {
		nl_socket_free(socket);
		nlmsg_free(msg);
		return __pusherrmsg(L, "Failed to send message to kernel");
	}

	lua_pushboolean(L, true);
	return 1;

nla_put_failure:
	nl_socket_free(socket);
	nlmsg_free(msg);
	return __pusherrmsg(L, "Failed to fill message with the given payload\n");
}

static const luaL_Reg messager_lib[] = {
	{"send", send_message},
	{NULL, NULL}
};

int luaopen_lunatik_messenger(lua_State *L)
{

	luaL_newlib(L, messager_lib);

	return 1;
}