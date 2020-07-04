#ifndef NETLINK_COMMOM_H
#define NETLINK_COMMOM_H

#ifdef _KERNEL
extern struct genl_family lunatik_family;
#include <net/genetlink.h>
#endif

#define LUNATIK_FAMILY "lunatik_family"
#define NKLUA_VERSION 1

enum lunatik_operations {
	CREATE_STATE,
	EXECUTE_CODE,
};

enum lunatik_attrs {
	STATE_NAME = 1,
	MAX_ALLOC,
	CODE,
	ATTRS_COUNT
#define ATTRS_MAX (ATTRS_COUNT - 1)
};

#endif
