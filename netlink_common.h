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

#ifndef KLUA_NETLINK_COMMON_H
#define KLUA_NETLINK_COMMON_H

#include <linux/netlink.h>

#ifdef _KERNEL
#include <net/genetlink.h>
extern struct genl_family lunatik_family;
#endif

#define KLUA_NAME_MAXSIZE 64
#define KLUA_MAX_BCK_COUNT 32

#define LUNATIK_FAMILY "lunatik_family"

#if PAGE_SIZE < 8192UL
#define KLUA_PAYLOAD_MAXSIZE PAGE_SIZE
#define KLUA_MAX_FRAGS       16
#else
#define KLUA_PAYLOAD_MAXSIZE 8192UL
#define KLUA_MAX_FRAGS       8
#endif

#define KLUA_SCRIPTNAME_MAXSIZE 255   /* Max length of Lua script name  */

#define KLUA_PAYLOAD_SIZE(x) (KLUA_PAYLOAD_MAXSIZE - NLMSG_SPACE(x))

#define KLUA_SCRIPT_FRAG_SIZE \
	(KLUA_PAYLOAD_SIZE(sizeof(struct klua_nl_script)))

#define KLUA_LIST_FRAG_SIZE \
	(KLUA_PAYLOAD_SIZE(sizeof(struct klua_nl_list)))

#define KLUA_DATA_MAXSIZE \
	(KLUA_PAYLOAD_SIZE(sizeof(struct klua_nl_data)))

#define KLUA_SCRIPT_MAXSIZE (KLUA_SCRIPT_FRAG_SIZE * KLUA_MAX_FRAGS) /* +- 64k */

#define KLUA_LIST_MAXSIZE (KLUA_LIST_FRAG_SIZE * KLUA_MAX_FRAGS) /* +- 64k */

#define KLUA_MAX_STATES (KLUA_LIST_MAXSIZE / sizeof(struct klua_nl_state))

/* KLua netlink message types */
enum {
	CREATE_STATE = 16,	     /* KLua create state msg type      */
	DESTROY_STATE,           /* KLua destroy state msg type     */
	LIST_STATES,             /* KLua list states msg type       */
	EXECUTE_CODE,            /* KLua execute states msg type    */
	DESTROY_ALL_STATES,      /* KLua destroy all states msg type*/
};

enum attributes_ids{
	STATE_NAME = 1,
	MAX_ALLOC,
	LUA_CODE,
	SCRIPT_NAME,
	SCRIPT_SIZE,
	FRAG_SEQ,
	FRAG_OFFSET,
	ATTR_COUNT,
#define ATTR_MAX (ATTR_COUNT - 1)
};

/* KLua netlink header flags */
#define NLM_F_REQUEST 	0x01	  /* A request message             */
#define NLM_F_MULTI 	0x02	  /* Multipart message             */
#define NLM_F_DONE		0x04	  /* Last message                  */
#define NLM_F_INIT		0x08	  /* First message                 */
#define NLM_F_ERR		0x0F	  /* A error msg*/

#define KLUA_MIN_ALLOC_BYTES (32 * 1024UL)

struct klua_nl_state {
	char  name[KLUA_NAME_MAXSIZE];
	__u32 maxalloc;           /* Max allocated bytes           */
	__u32 curralloc;          /* Current allocated bytes       */
};

struct klua_nl_fragment {
	__u32 seq;                /* Current frament number        */
	__u32 offset;             /* Current number of items sent  */
};

struct klua_nl_list {
	__u32 total;              /* Total number of items         */
	struct klua_nl_fragment frag;
};

struct klua_nl_destroy {
	char  name[KLUA_NAME_MAXSIZE];
};

struct klua_nl_data {
	__u32 total;              /* Total number of bytes         */
	char  name[KLUA_NAME_MAXSIZE];
};

struct klua_nl_script {
	__u32 total;              /* Total number of bytes         */
	char  name[KLUA_NAME_MAXSIZE];
	char  script[KLUA_SCRIPTNAME_MAXSIZE];
	struct klua_nl_fragment frag;
};

#endif /* KLUA_NETLINK_COMMON_H */
