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