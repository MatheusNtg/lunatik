#ifndef NETLINK_COMMOM_H
#define NETLINK_COMMOM_H

#ifdef _KERNEL
extern struct genl_family lunatik_family;
#include <net/genetlink.h>
#endif

#define KLUA_MAX_SCRIPT_SIZE (3000) // TODO Find, a size more precise

/*Lunatik generic netlink protocol flags*/
#define KLUA_INIT		   0x01	/* Initializes the needed variables for script execution */
#define KLUA_MULTIPART_MSG 0x02 /* A Fragment of a multipart message  					 */
#define KLUA_LAST_MSG	   0x04 /* Last message of a multipart message 					 */ 

#define LUNATIK_FAMILY "lunatik_family"
#define NKLUA_VERSION 1

enum lunatik_operations {
	CREATE_STATE,
	EXECUTE_CODE,
	DESTROY_STATE,
};

enum lunatik_attrs {
	STATE_NAME = 1,
	MAX_ALLOC,
	CODE,
	FLAGS,
	SCRIPT_SIZE,
	ATTRS_COUNT
#define ATTRS_MAX (ATTRS_COUNT - 1)
};

#endif
