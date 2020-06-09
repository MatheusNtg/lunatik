#ifndef __LUNATIK_NETLINK
#define __LUNATIK_NETLINK

#include <linux/module.h>
#include <linux/version.h>

#ifdef _KERNEL
#include <net/genetlink.h>
MODULE_LICENSE("GPL");
#endif

#define LUNATIK_FAMILY "lunatik_family"

enum lunatik_operations{
	CREATE_STATE,
	LIST_STATES,
	DELETE_STATE,
	EXECUTE_CODE,
	DESTROY_ALL_STATES,
};


enum attributes_ids{
	STATE_NAME = 1,
	MAX_ALLOC,
	EXEC_CODE,
	ATTR_COUNT,
#define ATTR_MAX (ATTR_COUNT - 1)
};

extern struct genl_family lunatik_family;


#endif