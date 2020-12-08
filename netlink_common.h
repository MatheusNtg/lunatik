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

#ifndef NETLINK_COMMOM_H
#define NETLINK_COMMOM_H

#include "lunatik_conf.h"

#ifdef _KERNEL
extern struct genl_family lunatik_family;
#include <net/genetlink.h>
#endif /* _KERNEL */

#define LUNATIK_FRAGMENT_SIZE	(10) /* TODO Find, a more precise size */
#define DELIMITER	(3) /* How many delimiters will be necessary in each part of the message */
#define LUNATIK_MAX_SCRIPT_SIZE	(64000)

#define LUNATIK_INIT	(0x01)
#define LUNATIK_MULTI	(0x02)
#define LUNATIK_DONE	(0x04)

#define LUNATIK_FAMILY	("lunatik_family")
#define LUNATIK_NLVERSION	(1)

enum lunatik_operations {
	CREATE_STATE = 1, /* Starts at 1 because 0 is used by generic netlink */
	DO_STRING,
	DESTROY_STATE,
	LIST_STATES,
	DATA,
	DATA_INIT,
	GET_STATE,
	GET_CURRALLOC,
	PUT_STATE,
};

enum lunatik_attrs {
	STATE_NAME = 1,
	MAX_ALLOC,
	STATES_LIST,
	STATES_COUNT,
	PARTS,
	CODE,
	FLAGS,
	SCP_PACKET_TYPE,
	PAYLOAD_SIZE,
	SCRIPT_NAME,
	SCRIPT_SIZE,
	STATES_LIST_EMPTY,
	OP_SUCESS,
	OP_ERROR,
	LUNATIK_DATA,
	LUNATIK_DATA_LEN,
	CURR_ALLOC,
	STATE_NOT_FOUND,
	NOT_IN_USE,
	ATTRS_COUNT
#define ATTRS_MAX	(ATTRS_COUNT - 1)
};

/*scp stands for Send Code Protocol*/
enum scp_packet_type {
	INIT,
	PAYLOAD,
	DONE,
	ERROR
};

struct scp_header {
	char state_name[LUNATIK_NAME_MAXSIZE];
	enum scp_packet_type type;
	size_t payload_size;
	size_t script_size;
};

struct scp_payload {
	char *payload;
};

struct scp_packet {
	struct scp_header *header;
	struct scp_payload *payload;
};

#endif /* NETLINK_COMMOM_H */
