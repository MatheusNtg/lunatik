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

static struct nl_msg *prepare_message(struct lunatik_control *ctrl, int command)
{
	struct nl_msg *msg;

	if ((msg = nlmsg_alloc()) == NULL) {
		printf("Failed to allocate a new message\n");
		return NULL;
	}

	if ((genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, ctrl->family,
					0, 0, command, LUNATIK_NLVERSION)) == NULL) {
		printf("Failed to put generic netlink message header\n");
		return NULL;
	}

	return msg;
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

int lunatikC_create(struct lunatik_control *ctrl, struct lunatik_nl_state *cmd)
{
	struct nl_msg *msg;
	int ret = -1;

	if ((msg = prepare_message(ctrl, CREATE_STATE)) == NULL)
		return ret;

	NLA_PUT_STRING(msg, STATE_NAME, cmd->name);
	NLA_PUT_U32(msg, MAX_ALLOC, cmd->maxalloc);

	if ((ret = nl_send_auto(ctrl->sock, msg)) < 0) {
		printf("Failed to send message to kernel\n %s\n", nl_geterror(ret));
		return ret;
	}

	return 0;

nla_put_failure:
	printf("Failed to put attributes on message\n");
	return ret;
}

int lunatikC_destroy(struct lunatik_control *ctrl, const char *name)
{
	struct nl_msg *msg;
	int ret = -1;

	if ((msg = prepare_message(ctrl, DESTROY_STATE)) == NULL)
		return ret;

	NLA_PUT_STRING(msg, STATE_NAME, name);

	if ((ret = nl_send_auto(ctrl->sock, msg)) < 0) {
		printf("Failed to send destroy message:\n %s\n", nl_geterror(ret));
		return ret;
	}

	return 0;

nla_put_failure:
	printf("Failed to put attributes on netlink message\n");
	return ret;
}

int lunatikC_execute(struct lunatik_control *ctrl, const char *state_name,
    const char *script, size_t total_code_size)
{
	struct nl_msg *msg;
	char *fragment;
	int ret = -1;
	int parts = 0;

	if (total_code_size <= LUNATIK_FRAGMENT_SIZE) {
		if ((msg = prepare_message(ctrl, EXECUTE_CODE)) == NULL)
			return ret;

		NLA_PUT_STRING(msg, STATE_NAME, state_name);
		NLA_PUT_STRING(msg, CODE, script);
		NLA_PUT_U8(msg, FLAGS, LUNATIK_INIT | LUNATIK_DONE);
		NLA_PUT_U32(msg, SCRIPT_SIZE, total_code_size);

		if ((ret = nl_send_auto(ctrl->sock, msg)) < 0) {
			printf("Failed to send message\n %s\n", nl_geterror(ret));
			nlmsg_free(msg);
			return ret;
		}

		nlmsg_free(msg);
	} else {
		parts = (total_code_size % LUNATIK_FRAGMENT_SIZE == 0) ?
			total_code_size / LUNATIK_FRAGMENT_SIZE :
			(total_code_size / LUNATIK_FRAGMENT_SIZE) + 1;

		fragment = malloc(sizeof(char) * LUNATIK_FRAGMENT_SIZE);

		for (int i = 0; i < parts - 1; i++) {
			if ((msg = prepare_message(ctrl, EXECUTE_CODE)) == NULL){
				nlmsg_free(msg);
				return ret;
			}

			strncpy(fragment, script + (i * LUNATIK_FRAGMENT_SIZE), LUNATIK_FRAGMENT_SIZE);

			NLA_PUT_STRING(msg, STATE_NAME, state_name);
			NLA_PUT_STRING(msg, CODE, fragment);

			if (i == 0){
				NLA_PUT_U8(msg, FLAGS, LUNATIK_INIT | LUNATIK_MULTI);
				NLA_PUT_U32(msg, SCRIPT_SIZE, total_code_size);
			} else {
				NLA_PUT_U8(msg, FLAGS, LUNATIK_MULTI);
			}

			if ((ret = nl_send_auto(ctrl->sock, msg)) < 0) {
				printf("Failed to send fragment\n %s\n", nl_geterror(ret));
				nlmsg_free(msg);
				return ret;
			}

			nlmsg_free(msg);
		}

		if ((msg = prepare_message(ctrl, EXECUTE_CODE)) == NULL)
			return ret;

		strncpy(fragment, script + ((parts - 1) * LUNATIK_FRAGMENT_SIZE), LUNATIK_FRAGMENT_SIZE);

		NLA_PUT_STRING(msg, STATE_NAME, state_name);
		NLA_PUT_STRING(msg, CODE, fragment);
		NLA_PUT_U8(msg, FLAGS, LUNATIK_DONE);

		if ((ret = nl_send_auto(ctrl->sock, msg)) < 0) {
			printf("Failed to send fragment\n %s\n", nl_geterror(ret));
			return ret;
		}

		free(fragment);
		nlmsg_free(msg);
	}

	return 0;

nla_put_failure:
	printf("Failed to put netlink attributes\n");
	nlmsg_free(msg);
	return ret;
}

#ifndef _UNUSED
int nflua_control_list(struct nflua_control *ctrl)
{
	struct nlmsghdr nlh;
	struct iovec iov;
	int ret = -EPERM;

	if (ctrl->state != NFLUA_LINK_READY)
		return ret;

	nlh.nlmsg_len = NLMSG_LENGTH(0);
	nlh.nlmsg_type = NFLMSG_LIST;
	nlh.nlmsg_flags = NFLM_F_REQUEST;
	nlh.nlmsg_seq = ++(ctrl->seqnum);
	nlh.nlmsg_pid = ctrl->pid;

	iov.iov_base = &nlh;
	iov.iov_len = NLMSG_HDRLEN;

	if ((ret = sendcmd(ctrl->fd, &iov, 1)) < 0)
		return ret;

	ctrl->state = NFLUA_PENDING_REPLY;
	return ret;
}
#endif /* _UNUSED */

int lunatikC_init(struct lunatik_control *ctrl, uint32_t pid)
{
	int err = -1;

	if (ctrl == NULL)
		return -EINVAL;

	if ((ctrl->sock = nl_socket_alloc()) == NULL)
		return err;

	if ((err = genl_connect(ctrl->sock)))
		return err;

	if ((ctrl->family = genl_ctrl_resolve(ctrl->sock, LUNATIK_FAMILY)) < 0)
		return err;

	ctrl->pid = pid;

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

void nflua_data_close(struct nflua_data *dch)
{
	if (dch != NULL) {
		close(dch->fd);
		dch->fd = -1;
	}
}
#endif /* _UNUSED */
