/*
 * Copyright (c) 2020 Matheus Rodrigues <matheussr61@gmail.com>
 * Copyright (C) 2017-2019	CUJO LLC
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

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <linux/netlink.h>

#include "lunatik.h"

#define MIN(x,y) ((x) < (y) ? (x) : (y))

static struct nl_msg *prepare_message(struct lunatik_session *session, int command, int flags)
{
	struct nl_msg *msg;

	if ((msg = nlmsg_alloc()) == NULL) {
		printf("Failed to allocate a new message\n");
		return NULL;
	}

	if ((genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, session->family,
					0, 0, command, LUNATIK_NLVERSION)) == NULL) {
		printf("Failed to put generic netlink message header\n");
		return NULL;
	}

	NLA_PUT_U8(msg, FLAGS, flags);

	return msg;
nla_put_failure:
	printf("Failed to put attributes preparing the message\n");
	return NULL;
}

static int send_simple_msg(struct lunatik_session *session, int command, int flags)
{
	struct nl_msg *msg;
	int err = -1;

	if ((msg = prepare_message(session, command, flags)) == NULL) {
		printf("Error preparing message\n");
		goto error;
	}

	if ((err = nl_send_auto(session->sock, msg)) < 0) {
		printf("Failed sending message to kernel\n");
		goto error;
	}

	nlmsg_free(msg);
	return 0;

error:
	nlmsg_free(msg);
	return err;
}

static int send_fragment(struct lunatik_session *session, const char *original_script, int offset,
	const char *state_name, int flags)
{
	struct nl_msg *msg;
	char *fragment;
	int err = -1;
	if ((msg = prepare_message(session, EXECUTE_CODE, 0)) == NULL){
		nlmsg_free(msg);
		return err;
	}

	if ((fragment = malloc(sizeof(char) * LUNATIK_FRAGMENT_SIZE)) == NULL) {
		printf("Failed to allocate memory to code fragment\n");
		return -ENOMEM;
	}
	strncpy(fragment, original_script + (offset * LUNATIK_FRAGMENT_SIZE), LUNATIK_FRAGMENT_SIZE);

	NLA_PUT_STRING(msg, STATE_NAME, state_name);
	NLA_PUT_STRING(msg, CODE, fragment);

	if (offset == 0)
		NLA_PUT_U32(msg, SCRIPT_SIZE, strlen(original_script));
		
	NLA_PUT_U8(msg, FLAGS, flags);
	
	if ((err = nl_send_auto(session->sock, msg)) < 0) {
		printf("Failed to send fragment\n %s\n", nl_geterror(err));
		nlmsg_free(msg);
		return err;
	}

	nlmsg_free(msg);

	return 0;

nla_put_failure:
	printf("Failed putting attributes on the message\n");
	free(fragment);
	return err;
}

#ifndef _UNUSED
static int handle_list_response(struct nflua_control *ctrl,
	  struct nflua_response *r, struct nlmsghdr *nh, char *buffer)
{
	struct nflua_nl_list *list;
	struct nflua_nl_fragment *frag;
	struct nflua_nl_state *desc;
	size_t offset;
	size_t currentsize;

	if (nh->nlmsg_flags & NFLM_F_INIT) {
		list = NLMSG_DATA(nh);
		frag = &list->frag;
		desc = (struct nflua_nl_state *)(list + 1);
		currentsize = NLMSG_PAYLOAD(nh, sizeof(struct nflua_nl_list));

		r->type = NFLMSG_LIST;
		r->count = list->total;
		r->total_size = list->total * sizeof(struct nflua_nl_state);

		if (r->total_size > NFLUA_LIST_MAXSIZE)
			return -EMSGSIZE;

	} else {
		frag = NLMSG_DATA(nh);
		desc = (struct nflua_nl_state *)(frag + 1);
		currentsize = NLMSG_PAYLOAD(nh, sizeof(struct nflua_nl_fragment));
	}

	offset = frag->offset * sizeof(struct nflua_nl_state);

	if (offset + currentsize > NFLUA_LIST_MAXSIZE)
		return -EMSGSIZE;

	memcpy(buffer + offset, desc, currentsize);

	ctrl->state =
		nh->nlmsg_flags & NFLM_F_DONE ? NFLUA_LINK_READY : NFLUA_RECEIVING_REPLY;

	return 0;
}

int nflua_control_receive(struct nflua_control *ctrl,
		struct nflua_response *nr, char *buffer)
{
	struct iovec iov = { ctrl->buffer, NFLUA_PAYLOAD_MAXSIZE };
	struct sockaddr_nl sa;
	struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
	struct nlmsghdr *nh;
	ssize_t len, ret = -1;

	if (nr == NULL || (ctrl->state != NFLUA_PENDING_REPLY
		  && ctrl->state != NFLUA_RECEIVING_REPLY))
		return -EPERM;

	if ((len = recvmsg(ctrl->fd, &msg, 0)) < 0)
		return len;

	nh = (struct nlmsghdr *)ctrl->buffer;
	if (NLMSG_OK(nh, len) == 0) {
		ctrl->state = NFLUA_PROTOCOL_OUTOFSYNC;
		return -EBADMSG;
	}

	if (nh->nlmsg_seq != ctrl->seqnum) {
		ctrl->state = NFLUA_PROTOCOL_OUTOFSYNC;
		return -EPROTO;
	}

	for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
		ret = 0;
		switch (nh->nlmsg_type) {
		case NFLMSG_CREATE:
		case NFLMSG_DESTROY:
		case NFLMSG_EXECUTE:
		case NLMSG_ERROR:
			nr->type = nh->nlmsg_type;
			ctrl->state = NFLUA_LINK_READY;
			break;
		case NFLMSG_LIST:
			ret = handle_list_response(ctrl, nr, nh, buffer);
			break;
		default:
			nr->type = -1;
			ctrl->state = NFLUA_LINK_READY;
		}
		if (ret < 0)
			break;
	}

	return ret < 0 ? ret : ctrl->state != NFLUA_LINK_READY;
}
#endif /* _UNUSED */

static int receive_op_result(struct lunatik_session *session){
	int ret;

	if ((ret = nl_recvmsgs_default(session->sock))) {
		printf("Failed to receive message from kernel: %s\n", nl_geterror(ret));
		return ret;
	}

	nl_wait_for_ack(session->sock);

	if (session->cb_result == CB_ERROR)
		return -1;

	return 0;
}

int lunatikS_create(struct lunatik_session *session, struct lunatik_state *cmd)
{
	struct nl_msg *msg;
	int ret = -1;

	if ((msg = prepare_message(session, CREATE_STATE, 0)) == NULL)
		return ret;

	NLA_PUT_STRING(msg, STATE_NAME, cmd->name);
	NLA_PUT_U32(msg, MAX_ALLOC, cmd->maxalloc);

	if ((ret = nl_send_auto(session->sock, msg)) < 0) {
		printf("Failed to send message to kernel\n %s\n", nl_geterror(ret));
		return ret;
	}
	
	return receive_op_result(session);

nla_put_failure:
	printf("Failed to put attributes on message\n");
	return ret;
}

int lunatikS_destroy(struct lunatik_session *session, const char *name)
{
	struct nl_msg *msg;
	int ret = -1;

	if ((msg = prepare_message(session, DESTROY_STATE, 0)) == NULL)
		return ret;

	NLA_PUT_STRING(msg, STATE_NAME, name);

	if ((ret = nl_send_auto(session->sock, msg)) < 0) {
		printf("Failed to send destroy message:\n %s\n", nl_geterror(ret));
		return ret;
	}

	return receive_op_result(session);

nla_put_failure:
	printf("Failed to put attributes on netlink message\n");
	return ret;
}

int lunatikS_execute(struct lunatik_session *session, const char *state_name,
    const char *script, size_t total_code_size)
{
	int err = -1;
	int parts = 0;

	if (total_code_size <= LUNATIK_FRAGMENT_SIZE) {
		err = send_fragment(session, script, 0, state_name, LUNATIK_INIT | LUNATIK_DONE);
		if (err)
			return err;
	} else {
		parts = (total_code_size % LUNATIK_FRAGMENT_SIZE == 0) ?
			total_code_size / LUNATIK_FRAGMENT_SIZE :
			(total_code_size / LUNATIK_FRAGMENT_SIZE) + 1;

		for (int i = 0; i < parts - 1; i++) {
			if (i == 0)
				err = send_fragment(session, script, i, state_name, LUNATIK_INIT | LUNATIK_MULTI);
			else
				err = send_fragment(session, script, i, state_name, LUNATIK_MULTI);

			nl_wait_for_ack(session->sock);

			if (err)
				return err;
		}

		err = send_fragment(session, script, parts - 1, state_name, LUNATIK_DONE);
		if (err)
			return err;
	}

	return receive_op_result(session);
}

int lunatikS_list(struct lunatik_session *session)
{
	int err = -1;

	if ((err = send_simple_msg(session, LIST_STATES, LUNATIK_INIT)))
		return err;

	nl_recvmsgs_default(session->sock);
	nl_wait_for_ack(session->sock);

	session->status = SESSION_RECEIVING;

	while (session->status == SESSION_RECEIVING) {
		send_simple_msg(session, LIST_STATES, 0);
		nl_recvmsgs_default(session->sock);
		nl_wait_for_ack(session->sock);
	}

	return 0;
}

static int add_state_on_list(struct lunatik_state state, struct states_list *list)
{
	if (list->tail == list->list_size) {
		printf("Trying to add elements to the list out of bounds\n");
		return -1;
	} else {
		list->states[list->tail++] = state;
	}

	return 0;
}

static int init_list(struct states_list *list, int size)
{
	if ((list->states = malloc(size * sizeof(struct lunatik_state))) == NULL) {
		printf("Failed to allocate memory to the list\n");
		return -1;
	}

	list->list_size = size;
	list->tail = 0;

	return 0;
}

static int response_handler(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nh = nlmsg_hdr(msg);
	struct genlmsghdr *gnlh = genlmsg_hdr(nh);
	struct lunatik_session *session = (struct lunatik_session *) arg;
	struct nlattr * attrs_tb[ATTRS_COUNT + 1];
	struct lunatik_state state;
	int list_size;

	// nl_msg_dump(msg, stdout);

	if (nla_parse(attrs_tb, ATTRS_COUNT, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL))
	{
		printf("Error parsing attributes\n");
		session->cb_result = CB_ERROR;
		return NL_OK;
	}
	switch (gnlh->cmd)
	{
	case CREATE_STATE:
	case DESTROY_STATE:
	case EXECUTE_CODE:
		if (attrs_tb[OP_SUCESS] && nla_get_u8(attrs_tb[OP_SUCESS])) {
			session->cb_result = CB_SUCCESS;
		} else if (attrs_tb[OP_ERROR] && nla_get_u8(attrs_tb[OP_ERROR])) {
			session->cb_result = CB_ERROR;
		}
		break;
	case LIST_STATES:
		if (attrs_tb[FLAGS] && (nla_get_u8(attrs_tb[FLAGS])  & LUNATIK_INIT) && attrs_tb[STATES_COUNT]){
			session->status = SESSION_INIT_LIST;
			list_size = nla_get_u32(attrs_tb[STATES_COUNT]);
			init_list(&session->states_list, list_size);
		} else if (attrs_tb[FLAGS] && (nla_get_u8(attrs_tb[FLAGS]) & LUNATIK_DONE)) {
			session->status = SESSION_FREE;
		} else {
			session->status = SESSION_RECEIVING;
			if (!(attrs_tb[STATE_NAME] && attrs_tb[MAX_ALLOC] && attrs_tb[CURR_ALLOC]))
				goto nla_get_failure;
		
			strncpy(state.name, nla_get_string(attrs_tb[STATE_NAME]), LUNATIK_NAME_MAXSIZE);
			state.maxalloc = nla_get_u32(attrs_tb[MAX_ALLOC]);
			state.curralloc = nla_get_u32(attrs_tb[CURR_ALLOC]);
			add_state_on_list(state, &session->states_list);
		}
		break;
	default:
		break;
	}

	return NL_OK;

nla_get_failure:
	printf("Failed to get attributes\n");
	return NL_OK;
}

int lunatikS_init(struct lunatik_session *session, uint32_t pid)
{
	int err = -1;

	if (session == NULL)
		return -EINVAL;

	if ((session->sock = nl_socket_alloc()) == NULL)
		return err;

	if ((err = genl_connect(session->sock)))
		return err;

	if ((session->family = genl_ctrl_resolve(session->sock, LUNATIK_FAMILY)) < 0)
		return err;

	nl_socket_modify_cb(session->sock, NL_CB_MSG_IN, NL_CB_CUSTOM, response_handler, session);
	session->pid = pid;

	return 0;
}

#ifndef _UNUSED
void nflua_control_close(struct nflua_control *ctrl)
{
	if (ctrl != NULL) {
		close(ctrl->fd);
		ctrl->fd = -1;
		ctrl->state = NFLUA_SOCKET_CLOSED;
	}
}

int nflua_data_send(struct nflua_data *dch, const char *name,
		const char *payload, size_t len)
{
	struct nlmsghdr nlh;
	struct nflua_nl_data cmd;
	struct iovec iov[3];

	if (name == NULL || payload == NULL || len == 0 || len > NFLUA_DATA_MAXSIZE)
		return -EPERM;

	nlh.nlmsg_type = NFLMSG_DATA;
	nlh.nlmsg_seq = ++(dch->seqnum);
	nlh.nlmsg_pid = dch->pid;
	nlh.nlmsg_flags = NFLM_F_REQUEST | NFLM_F_DONE;
	nlh.nlmsg_len = NLMSG_SPACE(sizeof(struct nflua_nl_data)) + len;

	memset(&cmd, 0, sizeof(struct nflua_nl_data));
	memcpy(cmd.name, name, strnlen(name, NFLUA_NAME_MAXSIZE));
	cmd.total = len;

	iov[0].iov_base = &nlh;
	iov[0].iov_len = NLMSG_HDRLEN;
	iov[1].iov_base = &cmd;
	iov[1].iov_len = NLMSG_ALIGN(sizeof(struct nflua_nl_data));
	iov[2].iov_base = (void *)payload;
	iov[2].iov_len = len;

	return sendcmd(dch->fd, iov, 3);
}

static int handle_data_msg(char *state, char *buffer, struct nlmsghdr *nlh)
{
	struct nflua_nl_data *cmd = NLMSG_DATA(nlh);
	size_t datalen = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct nflua_nl_data));
	char *payload = ((char *)nlh) + NLMSG_SPACE(sizeof(struct nflua_nl_data));

	if (nlh->nlmsg_flags != (NFLM_F_REQUEST | NFLM_F_DONE))
			return -EPROTO;

	if (cmd->total > NFLUA_DATA_MAXSIZE || cmd->total != datalen)
		return -EMSGSIZE;

	memcpy(buffer, payload, datalen);

	if (state != NULL)
		strncpy(state, cmd->name, NFLUA_NAME_MAXSIZE);

	return datalen;
}

int nflua_data_receive(struct nflua_data *dch, char *state, char *buffer)
{
	struct iovec iov = {dch->buffer, NFLUA_PAYLOAD_MAXSIZE};
	struct sockaddr_nl sa;
	struct msghdr msg = {&sa, sizeof(sa), &iov, 1, NULL, 0, 0};
	struct nlmsghdr *nh;
	ssize_t len, ret = -EBADMSG;

	if (buffer == NULL)
		return -EINVAL;

	if ((len = recvmsg(dch->fd, &msg, 0)) < 0)
		return len;

	nh = (struct nlmsghdr *)dch->buffer;
	for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_type != NFLMSG_DATA)
			return -EPROTO;
		if ((ret = handle_data_msg(state, buffer, nh)) < 0)
			break;
	}

	return ret;
}

int nflua_data_init(struct nflua_data *dch, uint32_t pid)
{
	if (dch == NULL)
		return -EINVAL;

	if ((dch->fd = create_socket(pid)) < 0)
		return dch->fd;

	dch->pid = pid;
	dch->seqnum = 0;

	return 0;
}
	if (dch != NULL) {
		close(dch->fd);
		dch->fd = -1;
	}
}
#endif /* _UNUSED */
