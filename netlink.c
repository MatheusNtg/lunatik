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

struct lunatik_nl_state {
	char name[LUNATIK_NAME_MAXSIZE];
	size_t maxalloc;
	size_t curralloc;
};

extern struct lunatik_instance *lunatik_pernet(struct net *net);

static int lunatikN_newstate(struct sk_buff *buff, struct genl_info *info);
static int lunatikN_dostring(struct sk_buff *buff, struct genl_info *info);
static int lunatikN_close(struct sk_buff *buff, struct genl_info *info);
static int lunatikN_list(struct sk_buff *buff, struct genl_info *info);
static int lunatikN_data(struct sk_buff *buff, struct genl_info *info);
static int lunatikN_datainit(struct sk_buff *buff, struct genl_info *info);
static int lunatikN_sendstate(struct sk_buff *buff, struct genl_info *info);
static int lunatikN_getcurralloc(struct sk_buff *buff, struct genl_info *info);
static int lunatikN_putstate(struct sk_buff *buff, struct genl_info *info);

struct nla_policy lunatik_policy[ATTRS_COUNT] = {
	[STATE_NAME]  = { .type = NLA_STRING },
	[CODE]	      = { .type = NLA_STRING },
	[STATES_LIST] = { .type = NLA_STRING },
	[LUNATIK_DATA]= { .type = NLA_STRING },
	[LUNATIK_DATA_LEN] = { .type = NLA_U32},
	[PAYLOAD_SIZE] = { .type = NLA_U32 },
	[MAX_ALLOC]   = { .type = NLA_U32 },
	[CURR_ALLOC]  = { .type = NLA_U32},
	[SCRIPT_SIZE] = { .type = NLA_U32 },
	[OP_SUCESS]   = { .type = NLA_U8 },
	[OP_ERROR]    = { .type = NLA_U8 },
	[SCP_PACKET_TYPE]   = { .type = NLA_U8 }
};

static const struct genl_ops l_ops[] = {
	{
		.cmd    = CREATE_STATE,
		.doit   = lunatikN_newstate,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		/*Before kernel 5.2.0, each operation has its own policy*/
		.policy = lunatik_policy
#endif
	},
	{
		.cmd    = DO_STRING,
		.doit   = lunatikN_dostring,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = lunatik_policy
#endif
	},
	{
		.cmd    = DESTROY_STATE,
		.doit   = lunatikN_close,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = lunatik_policy
#endif
	},
	{
		.cmd    = LIST_STATES,
		.doit   = lunatikN_list,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = lunatik_policy
#endif
	},
	{
		.cmd    = DATA,
		.doit   = lunatikN_data,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = lunatik_policy
#endif
	},
	{
		.cmd    = DATA_INIT,
		.doit   = lunatikN_datainit,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = lunatik_policy
#endif
	},
	{
		.cmd    = GET_STATE,
		.doit   = lunatikN_sendstate,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = lunatik_policy
#endif
	},
	{
		.cmd    = GET_CURRALLOC,
		.doit   = lunatikN_getcurralloc,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = lunatik_policy
#endif
	},
	{
		.cmd    = PUT_STATE,
		.doit   = lunatikN_putstate,
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

static void fill_states_list(char *buffer, struct lunatik_instance *instance)
{
	struct lunatik_state *state;
	int bucket;
	int counter = 0;
	int states_count = atomic_read(&instance->states_count);

	hash_for_each_rcu(instance->states_table, bucket, state, node) {
		buffer += sprintf(buffer, "%s#", state->name);
		buffer += sprintf(buffer, "%ld#", state->curralloc);
		if (counter == states_count - 1)
			buffer += sprintf(buffer, "%ld", state->maxalloc);
		else
			buffer += sprintf(buffer, "%ld#", state->maxalloc);
		counter++;
	}
}

static void reply_with(int reply, int command, struct genl_info *info)
{
	struct sk_buff *obuff;
	void *msg_head;

	if ((obuff = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL)) == NULL) {
		pr_err("Failed allocating message to an reply\n");
		return;
	}

	if ((msg_head = genlmsg_put_reply(obuff, info, &lunatik_family, 0, command)) == NULL) {
		pr_err("Failed to put generic netlink header\n");
		return;
	}

	if (nla_put_u8(obuff, reply, 1)) {
		pr_err("Failed to put attributes on socket buffer\n");
		return;
	}

	genlmsg_end(obuff, msg_head);

	if (genlmsg_reply(obuff, info) < 0) {
		pr_err("Failed to send message to user space\n");
		return;
	}

	switch (reply) {
		case OP_ERROR:
			pr_debug("Operation error send to user space\n");
			break;
		case OP_SUCESS:
			pr_debug("Operation success send to user space\n");
			break;
	}

}

static void send_states_list(char *buffer, int flags, struct genl_info *info)
{
	struct sk_buff *obuff;
	void *msg_head;

	if ((obuff = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL)) == NULL) {
		pr_err("Failed allocating message to an reply\n");
		return;
	}

	if ((msg_head = genlmsg_put_reply(obuff, info, &lunatik_family, 0, LIST_STATES)) == NULL) {
		pr_err("Failed to put generic netlink header\n");
		return;
	}

	if (nla_put_string(obuff, STATES_LIST, buffer)) {
		pr_err("Failed to put attributes on socket buffer\n");
		return;
	}

	if (nla_put_u8(obuff, FLAGS, flags)) {
		pr_err("Failed to put attributes on socket buffer\n");
		return;
	}

	genlmsg_end(obuff, msg_head);

	if (genlmsg_reply(obuff, info) < 0) {
		pr_err("Failed to send message to user space\n");
		return;
	}

	pr_debug("Message sent to user space\n");
}

static int lunatikN_newstate(struct sk_buff *buff, struct genl_info *info)
{
	struct lunatik_instance *instance;
	struct lunatik_state *s;
	char *state_name;
	u32 *max_alloc;

	pr_debug("Received a CREATE_STATE message\n");

	instance = lunatik_pernet(genl_info_net(info));
	state_name = (char *)nla_data(info->attrs[STATE_NAME]);
	max_alloc = (u32 *)nla_data(info->attrs[MAX_ALLOC]);

	s = lunatik_netnewstate(state_name, *max_alloc, genl_info_net(info));

	if (s == NULL)
		goto error;

	if (s->inuse)
		goto error;

	reply_with(OP_SUCESS, CREATE_STATE, info);
	s->inuse = true;

	return 0;

error:
	reply_with(OP_ERROR, CREATE_STATE, info);
	return 0;
}

static int init_codebuffer(lunatik_State *s, struct scp_packet *packet)
{
	if (s->code_buffer != NULL || s->buffer_offset != 0) // Code buffer is already initialized
		return -1;

	if ((s->code_buffer = kmalloc(packet->header->script_size + 1, GFP_KERNEL)) == NULL)
		return -1;

	s->buffer_offset = 0;
	s->scriptsize = packet->header->script_size;

	return 0;
}

static void add_payload_to_buffer(lunatik_State *state, struct scp_packet *packet)
{
	memcpy(state->code_buffer + state->buffer_offset, packet->payload, packet->header->payload_size);
	state->buffer_offset += packet->header->payload_size;
}

static void debug_code(char *code)
{
	int i = 0;
	while(code[i] != '\0') {
		switch(code[i]){
			case '\t':
				pr_info("\\t");
				break;
			case '\n':
				pr_info("\\n");
				break;
			default:
				pr_info("%c", code[i]);
		}
		i++;
	}
	pr_info("\\0\n");
}

static void free_code_buffer(lunatik_State *state)
{
	kfree(state->code_buffer);
	state->scriptsize = 0;
	state->buffer_offset = 0;
	state->code_buffer = NULL;
}

static int dostring(lunatik_State *s)
{
	int err = 0;
	int base;

	s->code_buffer[s->scriptsize] = '\0';

	if (!lunatik_getstate(s)) {
		pr_err("Failed to get state\n");
		err = -1;
		goto out;
	}

	spin_lock_bh(&s->lock);
	base = lua_gettop(s->L);
	if ((err = luaL_dostring(s->L, s->code_buffer))) {
		pr_err("%s\n", lua_tostring(s->L, -1));
	}

	spin_unlock_bh(&s->lock);
	lunatik_putstate(s);
	lua_settop(s->L, base);

out:
	free_code_buffer(s);
	return err;
}

static char *get_scp_pack_type(enum scp_packet_type type)
{
	char *possible_values[] = {
		[INIT]    = "INIT PACKET",
		[ERROR]   = "ERROR PACKET",
		[DONE]	  = "DONE PACKET",
		[PAYLOAD] = "PAYLOAD PACKET"
	};

	return possible_values[type];
}

static int reassemble_packet(struct scp_packet *packet, struct genl_info *info)
{
	/*Header Content*/
	char *state_name;
	enum scp_packet_type type;
	size_t payload_size;
	size_t script_size;

	if (packet == NULL || packet->header == NULL)
		return -1;

	state_name   = nla_data(info->attrs[STATE_NAME]);
	type	     = *((enum scp_packet_type *)nla_data(info->attrs[SCP_PACKET_TYPE]));
	payload_size = *((int *)nla_data(info->attrs[PAYLOAD_SIZE]));
	script_size  = *((int*)nla_data(info->attrs[SCRIPT_SIZE]));

	if (payload_size != 0) {
		packet->payload = kmalloc(payload_size + 1, GFP_KERNEL);

		if (packet->payload == NULL)
			return -1;

		memcpy(packet->payload, nla_data(info->attrs[CODE]), payload_size);
		packet->payload[payload_size] = '\0';
	} else {
		packet->payload = NULL;
	}

	strncpy(packet->header->state_name, nla_data(info->attrs[STATE_NAME]), LUNATIK_NAME_MAXSIZE);
	packet->header->type = type;
	packet->header->payload_size = payload_size;
	packet->header->script_size = script_size;

	return 0;
}

static struct scp_packet *init_scp_packet(void)
{
	struct scp_packet *packet;
	struct scp_header *header;

	packet = kmalloc(sizeof(struct scp_packet), GFP_KERNEL);

	if (packet == NULL)
		return NULL;

	header = kmalloc(sizeof(struct scp_header), GFP_KERNEL);

	if (header == NULL) {
		kfree(packet);
		packet = NULL;
		return NULL;
	}

	packet->header = header;
	packet->payload = NULL;

	return packet;
}

static void free_scp_packet(struct scp_packet *packet)
{
	kfree(packet->header);
	kfree(packet->payload);
	packet->header = NULL;
	packet->payload = NULL;

	kfree(packet);
	packet = NULL;
}

#ifdef DEBUG
static void print_scp_packet(struct scp_packet *packet)
{
	pr_info("\n*******HEADER*******\n"
		"State name: %s \n"
		"Packet Type: %s \n"
		"Payload Size: %ld \n"
		"Script Size: %ld \n"
		"******PAYLOAD******\n"
		"%s"
		,packet->header->state_name,
		get_scp_pack_type(packet->header->type),
		packet->header->payload_size,
		packet->header->script_size,
		packet->payload);
}
#endif

static int lunatikN_dostring(struct sk_buff *buff, struct genl_info *info)
{
	lunatik_State *state;
	struct scp_packet *packet;

	if ((packet = init_scp_packet()) == NULL) {
		pr_info("Failed to initialize scp_packet on kernel\n");
		goto error;
	}

	if (reassemble_packet(packet, info)) {
		pr_info("Failed to reasseamble the scp_packet\n");
		free_scp_packet(packet);
		goto error;
	}

#ifdef DEBUG
	print_scp_packet(packet);
#endif

	if ((state = lunatik_netstatelookup(packet->header->state_name, genl_info_net(info))) == NULL) {
		pr_info("State %s not found\n", packet->header->state_name);
		goto error;
	}

	switch (packet->header->type)
	{
	case INIT:
		if (init_codebuffer(state, packet)) {
			free_scp_packet(packet);
			goto error;
		}
		break;
	case PAYLOAD:
		add_payload_to_buffer(state, packet);
		break;
	case DONE:
		if (dostring(state)) {
			free_scp_packet(packet);
			goto error;
		}

		free_code_buffer(state);
		break;
	case ERROR:
		free_scp_packet(packet);
		free_code_buffer(state);
		goto error;
		break;
	default:
		pr_err("Unknow scp_packet type\n");
		break;
	}

	free_scp_packet(packet);

	reply_with(OP_SUCESS, DO_STRING, info);
	return 0;

error:
	reply_with(OP_ERROR, DO_STRING, info);
	return 0;
}

static int lunatikN_close(struct sk_buff *buff, struct genl_info *info)
{
	char *state_name;

	state_name = (char *)nla_data(info->attrs[STATE_NAME]);

	pr_debug("Received a DESTROY_STATE command\n");

	if (lunatik_netclosestate(state_name, genl_info_net(info)))
		reply_with(OP_ERROR, DESTROY_STATE, info);
	else
		reply_with(OP_SUCESS, DESTROY_STATE, info);

	return 0;
}

static void send_init_information(int parts, int states_count, struct genl_info *info)
{
	struct sk_buff *obuff;
	void *msg_head;

	if ((obuff = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL)) == NULL) {
		pr_err("Failed allocating message to an reply\n");
		return;
	}

	if ((msg_head = genlmsg_put_reply(obuff, info, &lunatik_family, 0, LIST_STATES)) == NULL) {
		pr_err("Failed to put generic netlink header\n");
		return;
	}

	if (nla_put_u32(obuff, STATES_COUNT, states_count) || nla_put_u32(obuff, PARTS, parts)) {
		pr_err("Failed to put attributes on socket buffer\n");
		return;
	}

	if (nla_put_u8(obuff, FLAGS, LUNATIK_INIT)) {
		pr_err("Failed to put attributes on socket buffer\n");
		return;
	}

	genlmsg_end(obuff, msg_head);

	if (genlmsg_reply(obuff, info) < 0) {
		pr_err("Failed to send message to user space\n");
		return;
	}

	pr_debug("Message sent to user space\n");
}

static int init_replybuffer(struct lunatik_instance *instance, size_t size)
{
	struct reply_buffer *reply_buffer = &instance->reply_buffer;
	reply_buffer->buffer = kmalloc(size * (sizeof(struct lunatik_nl_state) + DELIMITER), GFP_KERNEL);

	if (reply_buffer->buffer == NULL) {
		pr_err("Failed to allocate memory to message buffer\n");
		return -1;
	}

	fill_states_list(reply_buffer->buffer, instance);
	reply_buffer->curr_pos_to_send = 0;

	reply_buffer->parts = ((strlen(reply_buffer->buffer) % LUNATIK_FRAGMENT_SIZE) == 0) ?
						  (strlen(reply_buffer->buffer) / LUNATIK_FRAGMENT_SIZE) :
						  (strlen(reply_buffer->buffer) / LUNATIK_FRAGMENT_SIZE) + 1;
	reply_buffer->status = RB_SENDING;
	return 0;
}

static void send_lastfragment(char *fragment, struct reply_buffer *reply_buffer, struct genl_info *info)
{
	strncpy(fragment, reply_buffer->buffer + ((reply_buffer->parts - 1) * LUNATIK_FRAGMENT_SIZE), LUNATIK_FRAGMENT_SIZE);
	send_states_list(fragment, LUNATIK_DONE, info);
}

static void send_fragment(char *fragment, struct reply_buffer *reply_buffer, struct genl_info *info)
{
	strncpy(fragment, reply_buffer->buffer + (reply_buffer->curr_pos_to_send * LUNATIK_FRAGMENT_SIZE), LUNATIK_FRAGMENT_SIZE);
	send_states_list(fragment, LUNATIK_MULTI, info);
	reply_buffer->curr_pos_to_send++;
}

static int lunatikN_list(struct sk_buff *buff, struct genl_info *info)
{
	struct lunatik_instance *instance;
	struct reply_buffer *reply_buffer;
	int states_count;
	char *fragment;
	int err = 0;
	u8 flags;

	pr_debug("Received a LIST_STATES command\n");

	instance = lunatik_pernet(genl_info_net(info));
	flags = *((u8 *)nla_data(info->attrs[FLAGS]));
	states_count = atomic_read(&instance->states_count);
	reply_buffer = &instance->reply_buffer;

	if ((fragment = kmalloc(LUNATIK_FRAGMENT_SIZE, GFP_KERNEL)) == NULL) {
		pr_err("Failed to allocate memory to fragment\n");
		return 0;
	}

	if (states_count == 0){
		reply_with(STATES_LIST_EMPTY, LIST_STATES, info);
		goto out;
	}

	if (reply_buffer->status == RB_INIT) {
		err = init_replybuffer(instance, states_count);
		if (err)
			reply_with(OP_ERROR, LIST_STATES, info);
		else
			send_init_information(reply_buffer->parts, states_count, info);
		goto out;
	}

	if (reply_buffer->curr_pos_to_send == reply_buffer->parts - 1) {
		send_lastfragment(fragment, reply_buffer, info);
		goto reset_reply_buffer;
	} else {
		send_fragment(fragment, reply_buffer, info);
	}

out:
	kfree(fragment);
	return 0;

reset_reply_buffer:
	reply_buffer->parts = 0;
	reply_buffer->status = RB_INIT;
	reply_buffer->curr_pos_to_send = 0;
	kfree(fragment);
	return 0;
}

static int init_data(lunatik_State *state, char *buffer, size_t size)
{
	if ((state->data.buffer = kmalloc(size, GFP_KERNEL)) == NULL) {
		pr_err("Failed to allocate memory to data buffer\n");
		return -1;
	}
	memcpy(state->data.buffer, buffer, size);
	state->data.size = size;
	return 0;
}

static void free_data(lunatik_State *state)
{
	kfree(state->data.buffer);
	state->data.size = 0;
}

static int handle_data(lua_State *L);

static int lunatikN_data(struct sk_buff *buff, struct genl_info *info)
{

	// pr_info("Estou simulando a execução de um recebimento de dado\n");
	lunatik_State *state;
	char *payload;
	char *state_name;
	u32 payload_len;
	int err = 0;
	int base;

	state_name = nla_data(info->attrs[STATE_NAME]);

	if ((state = lunatik_netstatelookup(state_name, genl_info_net(info))) == NULL) {
		pr_err("State %s not found\n", state_name);
		goto error;
	}

	payload = nla_data(info->attrs[LUNATIK_DATA]);
	payload_len = *((u32 *)nla_data(info->attrs[LUNATIK_DATA_LEN]));

	if(init_data(state, payload, payload_len)) goto error;

	if (!lunatik_getstate(state)) {
		pr_err("Failed to get state %s\n", state_name);
		free_data(state);
		goto error;
	}

	spin_lock_bh(&state->lock);

	base = lua_gettop(state->L);
	lua_pushcfunction(state->L, handle_data);
	lua_pushlightuserdata(state->L, &state->data);
	if (luaU_pcall(state->L, 1, 0)) {
		pr_err("%s\n", lua_tostring(state->L, -1));
		err = -1;
	}

unlock:
	spin_unlock_bh(&state->lock);
	lua_settop(state->L, base);
	lunatik_putstate(state);
	free_data(state);

	err ? reply_with(OP_ERROR, DATA, info) : reply_with(OP_SUCESS, DATA, info);

	return 0;

error:
	reply_with(OP_ERROR, DATA, info);
	return 0;
}

static int lunatikN_datainit(struct sk_buff *buff, struct genl_info *info)
{
	lunatik_State *state;
	char *name;

	name = nla_data(info->attrs[STATE_NAME]);

	if ((state = lunatik_netstatelookup(name, genl_info_net(info))) == NULL) {
		pr_err("Failed to find the state %s\n", name);
		reply_with(OP_ERROR, DATA_INIT, info);
		return 0;
	}

	state->usr_state_info = *info;

	reply_with(OP_SUCESS, DATA_INIT, info);

	return 0;
}

int lunatikN_send_data(lunatik_State *state, const char *payload, size_t size)
{
	struct sk_buff *obuff;
	void *msg_head;

	if ((obuff = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL)) == NULL) {
		pr_err("Failed allocating message to an reply\n");
		return 0;
	}

	if ((msg_head = genlmsg_put_reply(obuff, &state->usr_state_info, &lunatik_family, 0, DATA)) == NULL) {
		pr_err("Failed to put generic netlink header\n");
		return 0;
	}

	if (nla_put_string(obuff, LUNATIK_DATA, payload) ||
		nla_put_u32(obuff, LUNATIK_DATA_LEN, size)) {
		pr_err("Failed to put attributes on socket buffer\n");
		return 0;
	}

	genlmsg_end(obuff, msg_head);

	if (genlmsg_reply(obuff, &state->usr_state_info) < 0) {
		pr_err("Failed to send message to user space\n");
		return 0;
	}

	pr_debug("Message sent to user space\n");
	return 0;
}

static int sendstate_msg(lunatik_State *state, struct genl_info *info)
{
	struct sk_buff *obuff;
	void *msg_head;

	if ((obuff = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL)) == NULL) {
		pr_err("Failed allocating message to an reply\n");
		return -1;
	}

	if ((msg_head = genlmsg_put_reply(obuff, info, &lunatik_family, 0, GET_STATE)) == NULL) {
		pr_err("Failed to put generic netlink header\n");
		return -1;
	}

	if (nla_put_string(obuff, STATE_NAME, state->name) ||
		nla_put_u32(obuff, MAX_ALLOC, state->maxalloc) ||
		nla_put_u32(obuff, CURR_ALLOC, state->curralloc)) {
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

static int lunatikN_sendstate(struct sk_buff *buff, struct genl_info *info)
{
	lunatik_State *state;
	char *state_name;

	state_name = nla_data(info->attrs[STATE_NAME]);

	if(((state = lunatik_netstatelookup(state_name, genl_info_net(info))) == NULL)) {
		pr_err("State %s not found\n", state_name);
		reply_with(STATE_NOT_FOUND, GET_STATE, info);
		return 0;
	}

	if (state->inuse) {
		pr_info("State %s is already in use\n", state_name);
		reply_with(OP_ERROR, GET_STATE, info);
		return 0;
	}

	if (sendstate_msg(state, info)) {
		pr_err("Failed to send message to user space\n");
		reply_with(OP_ERROR, GET_STATE, info);
	}

	state->inuse = true;

	return 0;

}

static int send_curralloc(int curralloc, struct genl_info *info)
{
	struct sk_buff *obuff;
	void *msg_head;

	if ((obuff = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL)) == NULL) {
		pr_err("Failed allocating message to an reply\n");
		return -1;
	}

	if ((msg_head = genlmsg_put_reply(obuff, info, &lunatik_family, 0, GET_CURRALLOC)) == NULL) {
		pr_err("Failed to put generic netlink header\n");
		return -1;
	}

	if (nla_put_u32(obuff, CURR_ALLOC, curralloc)) {
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

static int lunatikN_getcurralloc(struct sk_buff *buff, struct genl_info *info)
{
	struct lunatik_state *s;
	char *state_name;

	pr_debug("Received a GET_CURRALLOC message\n");

	state_name = (char *)nla_data(info->attrs[STATE_NAME]);

	s = lunatik_netstatelookup(state_name, genl_info_net(info));

	if (s == NULL)
		goto error;

	if (send_curralloc(s->curralloc, info))
		goto error;

	return 0;

error:
	reply_with(OP_ERROR, GET_CURRALLOC, info);
	return 0;
}

static int lunatikN_putstate(struct sk_buff *buff, struct genl_info *info)
{
	struct lunatik_state *s;
	char *state_name;

	pr_debug("Received a PUT_STATE command\n");

	state_name = (char*)nla_data(info->attrs[STATE_NAME]);
	s = lunatik_netstatelookup(state_name, genl_info_net(info));

	if (s == NULL)
		goto error;

	if (!s->inuse) {
		reply_with(NOT_IN_USE, PUT_STATE, info);
		return 0;
	}

	if (lunatik_putstate(s))
		goto error;


	s->inuse = false;
	reply_with(OP_SUCESS, PUT_STATE, info);

	return 0;

error:
	reply_with(OP_ERROR, PUT_STATE, info);
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
