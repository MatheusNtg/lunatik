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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <net/sock.h>

#include "luautil.h"
#include "states.h"
#include "netlink_common.h"

#define STATES_PER_FRAG(header)  ((unsigned short)((KLUA_PAYLOAD_MAXSIZE \
        - NLMSG_SPACE(sizeof(header))) \
        / sizeof(struct klua_nl_state)))

#define INIT_FRAG_MAX_STATES	STATES_PER_FRAG(struct klua_nl_list)
#define FRAG_MAX_STATES 	STATES_PER_FRAG(struct klua_nl_fragment)

#define STATE_OFFSET(hdrptr, hdrsz) \
	((struct klua_nl_state *)((char *)hdrptr + NLMSG_ALIGN(hdrsz)))

#define DATA_RECV_FUNC "__receive_callback"

extern struct klua_communication *klua_pernet(struct net *);

struct nla_policy const l_policy[ATTR_COUNT] = {
	[STATE_NAME] = {.type = NLA_STRING},
	[LUA_CODE]   = {.type = NLA_STRING},
	[SCRIPT_NAME]= {.type = NLA_STRING},
	[MAX_ALLOC]  = {.type = NLA_U32},
	[SCRIPT_SIZE]= {.type = NLA_U32},
	[FRAG_SEQ]	 = {.type = NLA_U32},
	[FRAG_OFFSET]= {.type = NLA_U32},
};

static int klua_create_state(struct sk_buff *buff, struct genl_info *info);
static int klua_list_states(struct sk_buff *buff, struct genl_info *info);
static int klua_execute_code(struct sk_buff *buff, struct genl_info *info);
static int klua_destroy_state(struct sk_buff *buff, struct genl_info *info);
static int klua_destroy_all_states(struct sk_buff *buff, struct genl_info *info);

static const struct genl_ops l_ops[] = {
	{
		.cmd    = CREATE_STATE,
		.doit   = klua_create_state,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		/*Before kernel 5.2.0, each operation has its own policy*/
		.policy = l_policy
#endif
	},
	{
		.cmd    = LIST_STATES,
		.doit   = klua_list_states,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = l_policy
#endif
	},
	{
		.cmd    = EXECUTE_CODE,
		.doit   = klua_execute_code,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = l_policy
#endif
	},
	{
		.cmd    = DESTROY_STATE,
		.doit   = klua_destroy_state,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = l_policy
#endif
	},
	{
		.cmd    = DESTROY_ALL_STATES,
		.doit   = klua_destroy_all_states,
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
	.netnsok = true, /*Make this family visible for all namespaces*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
	.policy  = l_policy,
#endif
	.module  = THIS_MODULE,
	.ops     = l_ops,
	.n_ops   = ARRAY_SIZE(l_ops),
};

struct list_frag {
	struct klua_nl_state *state;
	unsigned short offset;
	unsigned short total;
};

struct list_cursor {
	struct sock *sock;
	struct nlmsghdr *nlh;
	struct sk_buff *oskb;
	struct list_frag frag;
	unsigned short curr;
	unsigned short total;
};

struct klua_frag_request {
	char name[KLUA_NAME_MAXSIZE];
	char script[KLUA_SCRIPTNAME_MAXSIZE];
	u32 fragseq;
	char *buffer;
	size_t offset;
	size_t total;
	bool release;
};

struct klua_client {
	struct hlist_node node;
	struct mutex lock;
	struct klua_frag_request request;
	u32 pid;
	u32 seq;
	u16 msgtype;
};

static u32 hash_random __read_mostly;

#define pid_hash(pid) (jhash_1word(pid, hash_random) & (KLUA_MAX_BCK_COUNT - 1))

static struct klua_client *client_lookup(struct klua_communication *klc, u32 pid)
{
	struct klua_client *client;

	if (unlikely(klc == NULL))
		return NULL;

	hash_for_each_possible_rcu(klc->clients_table, client, node, pid_hash(pid)){
		if (client->pid == pid)
			return client;
	}
	return NULL;
}

static struct klua_client *client_create(struct klua_communication *klc, u32 pid)
{
	struct klua_client *client;

	if (unlikely(klc == NULL))
		return NULL;

	if ((client = kzalloc(sizeof(struct klua_client), GFP_ATOMIC)) == NULL)
		return NULL;

	mutex_init(&client->lock);
	client->pid = pid;
	hash_add_rcu(klc->clients_table, &client->node, pid_hash(pid));

	return client;
}

static inline struct klua_client *client_find_or_create(
		struct klua_communication *klc, u32 pid)
{
	struct klua_client *client = client_lookup(klc, pid);
	if (client == NULL)
		client = client_create(klc, pid);
	return client;
}

#ifndef LUNATIK_UNUSED

static void client_destroy(struct klua_communication *klc, u32 pid)
{
	struct klua_client *client = client_lookup(klc, pid);

	if (unlikely(client == NULL))
		return;

	hlist_del_rcu(&client->node);

	mutex_lock(&client->lock);
	if (client->request.release && client->request.buffer != NULL)
		kfree(client->request.buffer);
	mutex_unlock(&client->lock);

	kfree(client);
}

#endif /* LUNATIK_UNUSED */

//klua_reply(oskb, CREATE_STATE, NLM_F_DONE, 0, GFP_KERNEL, info)
static int klua_reply(u16 type, int flags, size_t len, gfp_t alloc, 
	struct genl_info *info)
{
	void *msg;
	struct sk_buff *skb;
	skb = genlmsg_new(len, alloc);

	if (skb == NULL){
		pr_debug("Failed to allocate a new generic netlink message\n");
		return -ENOMEM;
	}

	msg = genlmsg_put_reply(skb, info, &lunatik_family, flags, type);

	if (msg == NULL) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	genlmsg_end(skb, msg);
	
	pr_debug("Put reply with success\n");


	return genlmsg_reply(skb, info);
}

#ifndef LUNATIK_UNUSED

#define nlmsg_send(sock, skb, pid, group) \
       ((group == 0) ? kpi_nlmsg_unicast(sock, skb, pid) : \
               nlmsg_multicast(sock, skb, pid, group, GFP_ATOMIC))

int klua_nl_send_data(struct klua_state *s, u32 pid, u32 group,
		const char *payload, size_t len)
{
	struct sk_buff *skb;
	struct klua_nl_data *data;
	int flags, ret = -1;
	size_t size, hdrsize = NLMSG_ALIGN(sizeof(struct klua_nl_data));

	if (len > KLUA_DATA_MAXSIZE)
		return -EMSGSIZE;

	s->dseqnum++;
	flags = NFLM_F_REQUEST | NFLM_F_DONE;
	size = len + hdrsize;

	if ((ret = klua_reply(&skb, s->dseqnum, NFLMSG_DATA, flags,
		size, GFP_ATOMIC)) < 0) {
		pr_err("could not alloc data packet\n");
		return ret;
	}

	data = nlmsg_data((struct nlmsghdr *)skb->data);
	data->total = len;
	memcpy(data->name, s->name, KLUA_NAME_MAXSIZE);
	memcpy(((char *)data) + hdrsize, payload, len);

	ret = nlmsg_send(s->klc->sock, skb, pid, group);
	return ret < 0 ? ret : 0;
}

#endif /* LUNATIK_UNUSED */

static int klua_create_op(struct klua_communication *klc, struct genl_info *info)
{
	char *state_name = nla_data(info->attrs[STATE_NAME]);
	unsigned int *max_alloc = (unsigned int*) nla_data(info->attrs[MAX_ALLOC]);
	int ret = -1;
	struct klua_state *state;


	pr_debug("received CREATE_STATE command\n");

	state = net_state_create(klc, *max_alloc, state_name);

	if (state == NULL) {
		pr_err("could not create new lua state\n");
		return ret;
	}

	if ((ret = klua_reply(CREATE_STATE, NLM_F_DONE, 0, GFP_KERNEL, info)) < 0) {
		pr_err("could not alloc replying packet\n");
		return ret;
	}


	pr_debug("new state created: %.*s\n",
		(int)strnlen(state_name, KLUA_NAME_MAXSIZE), state_name);

	return ret;
}

static int klua_destroy_op(struct klua_communication *klc, struct genl_info *info)
{
	char *state_name = nla_data(info->attrs[STATE_NAME]);
	int ret = -1;

	pr_debug("received DESTROY_STATE command\n");

	pr_debug("state: %.*s\n",
		(int)strnlen(state_name, KLUA_NAME_MAXSIZE), state_name);

	if (net_state_destroy(klc, state_name)) {
		pr_err("could not destroy lua state\n");
		return ret;
	}

	if ((ret = klua_reply(DESTROY_STATE, NLM_F_DONE, 0, GFP_KERNEL, info)) < 0) {
		pr_err("could not replying\n");
		return ret;
	}

	return ret;
}

#ifndef LUNATIK_UNUSED

static void init_list_hdr(struct list_cursor *lc)
{
	struct nlmsghdr *onlh = (struct nlmsghdr *)lc->oskb->data;
	struct klua_nl_list *list;
	struct klua_nl_fragment *frag;

	if (lc->frag.offset == 0) {
		list = nlmsg_data(onlh);
		list->total = lc->total;

		frag = &list->frag;
		frag->seq = 0;

		lc->frag.state =
			STATE_OFFSET(list, sizeof(struct klua_nl_list));
	} else {
		frag = nlmsg_data(onlh);
		frag->seq = (unsigned int)
			((INIT_FRAG_MAX_STATES - lc->frag.offset)
				/ FRAG_MAX_STATES) + 1;

		lc->frag.state =
			STATE_OFFSET(frag, sizeof(struct klua_nl_fragment));
	}

	frag->offset = lc->frag.offset;
}

static int init_list_skb(struct list_cursor *lc)
{
	int flags, ret;
	unsigned short missing = lc->total - lc->curr;
	size_t skblen;

	lc->frag.offset = lc->curr;

	if (lc->frag.offset == 0) {
		skblen = NLMSG_ALIGN(sizeof(struct klua_nl_list));
		flags = NFLM_F_INIT;
		flags |= (lc->total > INIT_FRAG_MAX_STATES) ? NFLM_F_MULTI : 0;
		lc->frag.total = min(missing, INIT_FRAG_MAX_STATES);
	} else {
		skblen = NLMSG_ALIGN(sizeof(struct klua_nl_fragment));
		flags = NFLM_F_MULTI;
		lc->frag.total = min(missing, FRAG_MAX_STATES);
	}

	flags |= lc->frag.offset + lc->frag.total >= lc->total ? NFLM_F_DONE : 0;

	skblen += sizeof(struct klua_nl_state) * lc->frag.total;
	if ((ret = klua_reply(&(lc->oskb), lc->nlh->nlmsg_seq, NFLMSG_LIST,
				 flags, skblen, GFP_KERNEL)) < 0) {
		return ret;
	}

	init_list_hdr(lc);

	return 0;
}

static void write_state(struct klua_state *s, struct list_frag *f,
	unsigned short curr)
{
	struct klua_nl_state *nl_state = f->state + curr - f->offset;
	size_t namelen = strnlen(s->name, KLUA_NAME_MAXSIZE);

	memset(nl_state, 0, sizeof(struct klua_nl_state));
	memcpy(&nl_state->name, s->name, namelen);
	nl_state->maxalloc  = s->maxalloc;
	nl_state->curralloc = s->curralloc;
}

static int list_iter(struct klua_state *state, unsigned short *data)
{
	struct list_cursor *lc = container_of(data, struct list_cursor, total);
	struct sk_buff *skb;
	int ret;

	if (lc->oskb == NULL && (ret = init_list_skb(lc)) < 0) {
		pr_err("couldn't alloc replying packet\n");
		return ret;
	}

	if (state)
		write_state(state, &lc->frag, lc->curr++);

	if (lc->curr < lc->frag.offset + lc->frag.total)
		return 0;

	skb = lc->oskb;
	lc->oskb = NULL;

	if ((ret = kpi_nlmsg_unicast(lc->sock, skb, lc->nlh->nlmsg_pid)) != 0)
		pr_err("couldn't send reply packet. Error: %d\n", ret);

	return ret;
}


static int klua_list_op(struct klua_communication *klc, struct sk_buff *skb)
{
	int ret;
	struct list_cursor lcursor = {
		.sock = klc->sock,
		.nlh = (struct nlmsghdr *)skb->data,
		.oskb = NULL,
		.frag = {NULL, 0, 0},
		.curr = 0,
		.total = 0
	};

	pr_debug("received NFLMSG_LIST command\n");

	ret = klua_state_list(klc, &list_iter, &lcursor.total);
	if (ret != 0)
		goto out;

	pr_debug("total number of states: %u\n", lcursor.total);
	if (lcursor.total == 0)
		ret = list_iter(NULL, &lcursor.total);

out:
	if (ret != 0)
		pr_err("error listing states\n");

	return ret;
}

#endif

#ifndef LUNATIK_UNUSED
static int klua_doexec(lua_State *L)
{
	int error;
	struct klua_frag_request *req = lua_touserdata(L, 2);

	lua_pop(L, 1);

	luamem_newref(L);
	luamem_setref(L, -1, req->buffer, req->total, NULL);

	if (lua_getglobal(L, DATA_RECV_FUNC) != LUA_TFUNCTION)
		return luaL_error(L, "couldn't find receive function: %s\n",
				DATA_RECV_FUNC);

	lua_pushvalue(L, 1); /* pid */
	lua_pushvalue(L, 2); /* memory */

	error = lua_pcall(L, 2, 0, 0);

	luamem_setref(L, 2, NULL, 0, NULL);

	if (error)
		lua_error(L);

	return 0;
}
#endif

static int klua_exec(struct klua_communication *klc, u32 pid,
		struct klua_client *client)
{
	struct klua_frag_request *req = &client->request;
	struct klua_state *s;
	int error = 0;
	int base;

	if ((s = net_state_lookup(klc, client->request.name)) == NULL) {
		pr_err("lua state not found\n");
		return -ENOENT;
	}

	if (!klua_state_get(s)) {
		pr_err("couldn't increment state reference\n");
		return -ESTALE;
	}

	spin_lock_bh(&s->lock);
	if (s->L == NULL) {
		pr_err("invalid lua state");
		error = -ENOENT;
		goto unlock;
	}

	base = lua_gettop(s->L);

	if ((error = luaU_dostring(s->L, req->buffer, req->total,
					  req->script)) != 0) {
		pr_err("%s\n", lua_tostring(s->L, -1));
		error = -EIO;
	}

	lua_settop(s->L, base);
unlock:
	spin_unlock_bh(&s->lock);
	klua_state_put(s);
	return error;
}

static int init_request(struct klua_client *c, size_t total, bool allocate,
		char *buffer)
{
	struct klua_frag_request *request = &c->request;
	int ret = -EPROTO;

	pr_debug("creating client buffer id: %u size: %ld\n", c->pid, total);

	if (request->buffer != NULL) {
		pr_err("invalid client buffer state\n");
		return ret;
	}

	if (allocate && (buffer = kmalloc(total, GFP_KERNEL)) == NULL) {
		pr_err("could not alloc client buffer\n");
		return -ENOMEM;
	}

	request->offset = 0;
	request->total = total;
	request->buffer = buffer;
	request->release = allocate;

	return 0;
}

static inline void clear_request(struct klua_client *c)
{
	if (c != NULL) {
		pr_debug("clearing client %u request\n", c->pid);

		if(c->request.release && c->request.buffer != NULL)
			kfree(c->request.buffer);

		memset(&c->request, 0, sizeof(struct klua_frag_request));
	}
}

static int klua_reassembly(struct klua_client *client,
		struct klua_nl_fragment *frag, size_t len)
{
	struct klua_frag_request *request = &client->request;
	char *p = ((char *)frag) + NLMSG_ALIGN(sizeof(struct klua_nl_fragment));

	if (request->offset + len > request->total) {
		pr_err("Invalid message. Current offset: %ld\n"
		       "Packet data length: %ld of total %ld\n",
			request->offset, len, request->total);
		return -EMSGSIZE;
	}

	memcpy(request->buffer + request->offset, p, len);
	request->offset += len;

	return 0;
}

static int klua_handle_frag(struct klua_communication *klc,
		struct klua_client *client, struct nlmsghdr *nlh,
		struct klua_nl_fragment *frag, size_t datalen, struct genl_info *info)
{
	size_t unfragmax = KLUA_PAYLOAD_SIZE(sizeof(struct klua_nl_script));
	int ret;

	if (nlh->nlmsg_flags & NLM_F_MULTI) {
		if ((ret = klua_reassembly(client, frag, datalen)) < 0) {
			pr_err("payload assembly error %d\n", ret);
			goto out;
		}

		if (!(nlh->nlmsg_flags & NLM_F_DONE)) {
			pr_debug("waiting for next fragment\n");
			return 0;
		}

	} else if (client->request.total > unfragmax) {
		pr_err("invalid unfragmented payload size\n");
		ret = -EFAULT;
		goto out;
	}

	if ((ret = klua_exec(klc, nlh->nlmsg_pid, client)) < 0) {
		pr_err("could not execute / load data!\n");
		goto out;
	}

	if ((ret = klua_reply(EXECUTE_CODE, NLM_F_DONE, 0, GFP_KERNEL, info)) < 0) {
		pr_err("could not alloc replying packet\n");
		goto out;
	}

out:
	clear_request(client);
	return ret;
}

static int klua_execute_op(struct klua_communication *klc, struct sk_buff *skb,
		struct klua_client *client, struct genl_info *info)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
	struct klua_frag_request req;
	struct klua_nl_fragment *frag;
	struct klua_nl_script cmd;
	size_t datalen;

	req = client->request;

	memcpy(cmd.name  , req.name  , strlen(req.name));
	memcpy(cmd.script, req.script, strlen(req.script));
	cmd.frag.seq 	= req.fragseq;
	cmd.frag.offset = req.offset;
	cmd.total 		= req.total;


	pr_debug("received EXECUTE_CODE command\n");

	if (nlh->nlmsg_flags & NLM_F_INIT) {
		if (client->request.fragseq != 0) {
			pr_err("Non expected NFLMSG_EXECUTE init\n");
			return -EPROTO;
		}

		if (cmd.total > KLUA_SCRIPT_MAXSIZE) {
			pr_err("payload larger than allowed\n");
			return -EMSGSIZE;
		} else if (cmd.frag.seq != 0 || cmd.frag.offset != 0) {
			pr_err("invalid NFLMSG_EXECUTE fragment\n");
			return -EPROTO;
		}

		frag = &cmd.frag;
		datalen = nlh->nlmsg_len
			- NLMSG_SPACE(sizeof(struct klua_nl_script));

		init_request(client,
			     cmd.total,
			     cmd.total > KLUA_SCRIPT_FRAG_SIZE,
			     ((char *)nlmsg_data(nlh))
			     + NLMSG_ALIGN(sizeof(struct klua_nl_script)));

	} else {
		frag = nlmsg_data(nlh);
		if ((frag->seq - 1) != client->request.fragseq) {
			pr_err("EXECUTE_CODE fragment out of order\n");
			clear_request(client);
			return -EPROTO;
		} else if (frag->offset != client->request.offset) {
			pr_err("Invalid EXECUTE_CODE message."
			       "Expected offset: %ld but got %d\n",
				client->request.offset, frag->offset);
			clear_request(client);
			return -EMSGSIZE;
		}

		datalen = nlh->nlmsg_len
			- NLMSG_SPACE(sizeof(struct klua_nl_fragment));

		client->request.fragseq++;
	}

	return klua_handle_frag(klc, client, nlh, frag, datalen, info);
}

#ifndef LUNATIK_UNUSED

static int klua_data_op(struct klua_communication *klc, struct sk_buff *skb,
		struct klua_client *client)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
	struct klua_nl_data *cmd = nlmsg_data(nlh);
	size_t mlen = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct klua_nl_data));
	int ret;

	pr_debug("received NFLMSG_DATA command\n");

	if (nlh->nlmsg_flags != (NFLM_F_REQUEST | NFLM_F_DONE)) {
		pr_err("Malformed NFLMSG_DATA\n");
		return -EPROTO;
	}

	if (cmd->total > KLUA_DATA_MAXSIZE || cmd->total != mlen) {
		pr_err("invalid payload size\n");
		return -EMSGSIZE;
	}

	init_request(client, cmd->total, false,
		((char *)cmd) + NLMSG_ALIGN(sizeof(struct klua_nl_data)));

	memcpy(client->request.name, cmd->name, KLUA_NAME_MAXSIZE);

	if ((ret = klua_exec(klc, nlh->nlmsg_pid, client)) < 0)
		pr_err("could not execute / load data!\n");

	clear_request(client);
	return ret;
}

static inline int klua_unknown_op(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
	pr_err("received UNKNOWN command type %d\n", nlh->nlmsg_type);
	return -1;
}

#endif /* LUNATIK_UNUSED */

static void klua_handle_error(u16 type, struct genl_info *info)
{
	pr_debug("NFLua replying with error\n");

	if (klua_reply(type, NLM_F_ERR, 0, GFP_KERNEL, info) < 0) {
		pr_err("could not alloc replying packet\n");
		return;
	}
}

#ifndef LUNATIK_UNUSED

struct urelease_work {
	struct	work_struct w;
	u32	portid;
	struct  klua_communication *klc;
};

static void klua_urelease_event_work(struct work_struct *work)
{
	struct urelease_work *w = container_of(work, struct urelease_work, w);

	pr_debug("release client with pid %u\n", w->portid);
	client_destroy(w->klc, w->portid);

	kfree(w);
}

#endif /* LUNATIK_UNUSED */

static int klua_create_state(struct sk_buff *buff, struct genl_info *info)
{
	struct klua_client *client;
	int err;
	struct net *net;
	struct klua_communication *klc;

	err = -1;

	pr_debug("received a signal to create a state\n");

	if ((net = genl_info_net(info)) == NULL) {
		pr_err("Error getting net namespace\n");
		return err;
	}

	if ((klc = klua_pernet(net)) == NULL) {
		pr_err("Error getting private data from namespace\n");
		return err;
	}

	if (buff == NULL)
		return err;

	if ((client = client_find_or_create(klc, info->snd_portid)) == NULL){
		pr_err("Fail to find or create a client\n");
		return err;
	}

	mutex_lock(&client->lock);

	err = klua_create_op(klc, info);
	if (err < 0)
		klua_handle_error(CREATE_STATE, info);

	mutex_unlock(&client->lock);

	return err;
}

static int klua_list_states(struct sk_buff *buff, struct genl_info *info)
{
	return 0;
}

static int klua_execute_code(struct sk_buff *buff, struct genl_info *info)
{
	char *state_name;
	char *code_frag;
	char *script_name;
	u32 frag_seq;
	u32 frag_off;
	u32 script_size;

	struct klua_client *client;
	struct klua_frag_request req;
	int err;
	struct net *net;
	struct klua_communication *klc;

	err = -1;

	pr_debug("received a signal to execute an code\n");

	if ((net = genl_info_net(info)) == NULL) {
		pr_err("Error getting net namespace\n");
		return err;
	}

	if ((klc = klua_pernet(net)) == NULL) {
		pr_err("Error getting private data from namespace\n");
		return err;
	}

	if (buff == NULL)
		return err;

	if ((client = client_find_or_create(klc, info->snd_portid)) == NULL) {
		pr_err("Fail to find or create a client\n");
		return err;
	}

	state_name = nla_data(info->attrs[STATE_NAME]);
	code_frag  = nla_data(info->attrs[LUA_CODE]);
	script_name= nla_data(info->attrs[SCRIPT_NAME]);
	frag_seq   = *((u32 *)nla_data(info->attrs[FRAG_SEQ]));
	frag_off   = *((u32 *)nla_data(info->attrs[FRAG_OFFSET]));
	script_size= *((u32 *)nla_data(info->attrs[SCRIPT_SIZE]));


	memcpy(req.name, state_name, strlen(state_name));
	memcpy(req.buffer, code_frag, strlen(code_frag));
	memcpy(req.script, script_name, strlen(script_name));
	req.fragseq= frag_seq;
	req.offset = frag_off;
	req.total  = script_size;

	client->request = req;

	if ((err = klua_execute_op(klc, buff, client, info)))
		return err;

	return 0;
}

static int klua_destroy_state(struct sk_buff *buff, struct genl_info *info)
{
	struct klua_client *client;
	int err;
	struct net *net = genl_info_net(info);
	struct klua_communication *klc = klua_pernet(net);

	err = -1;

	pr_debug("received a signal to destroy a state\n");

	if ((net = genl_info_net(info)) == NULL) {
		pr_err("Error getting net namespace\n");
		return err;
	}

	if ((klc = klua_pernet(net)) == NULL) {
		pr_err("Error getting private data from namespace\n");
		return err;
	}

	if (buff == NULL)
		return err;

	if ((client = client_find_or_create(klc, info->snd_portid)) == NULL){
		pr_err("Fail to find or create a client\n");
		return err;
	}

	mutex_lock(&client->lock);

	err = klua_destroy_op(klc, info);
	if (err < 0)
		klua_handle_error(DESTROY_STATE, info);

	mutex_unlock(&client->lock);

	return err;
}

static int klua_destroy_all_states(struct sk_buff *buff, struct genl_info *info)
{
	return 0;
}
