/*
 * Copyright (c) 2020 Matheus Rodrigues <matheussr61@gmail.com>
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

#ifndef LUNATIK_H
#define LUNATIK_H

#include <sys/user.h>
#include <stdint.h>
#include <netlink/genl/genl.h>
#include "../netlink_common.h"
#include "../lunatik_conf.h"

enum callback_result {
    CB_SUCCESS,
    CB_ERROR,
};

struct lunatik_session {
    struct nl_sock *sock;
    enum callback_result cb_result;
    int family;
    uint32_t pid;
};

struct lunatik_state {
    struct lunatik_session *session;
    uint32_t maxalloc;
    uint32_t curralloc;
    char name[LUNATIK_NAME_MAXSIZE];
};

#ifndef _UNUSED
struct nflua_data {
    int fd;
    uint32_t pid;
    uint32_t seqnum;
    char state[NFLUA_NAME_MAXSIZE];
    char buffer[NFLUA_PAYLOAD_MAXSIZE];
};

static inline int nflua_control_getsock(const struct nflua_control *ctrl)
{
    return ctrl->fd;
}

static inline int nflua_control_getstate(const struct nflua_control *ctrl)
{
    return ctrl->state;
}

static inline int nflua_control_getpid(const struct nflua_control *ctrl)
{
    return ctrl->pid;
}
#endif /* _UNUSED */

static inline int lunatikS_isopen(const struct lunatik_session *session)
{
    return nl_socket_get_fd(session->sock) != -1;
}

int lunatikS_init(struct lunatik_session *session, uint32_t pid);

#ifndef _UNUSED
void nflua_control_close(struct nflua_control *ctrl);
#endif /*_UNUSED*/

int lunatikS_create(struct lunatik_session *session, struct lunatik_state *s);

int lunatikS_destroy(struct lunatik_session *session, const char *name);

int lunatikS_execute(struct lunatik_session *session, const char *state_name,
    const char *script, size_t total_code_size);

int lunatikS_list(struct lunatik_session *session);

#ifndef _UNUSED
int nflua_control_receive(struct nflua_control *ctrl,
        struct nflua_response *nr, char *buffer);

static inline int nflua_data_getsock(const struct nflua_data *dch)
{
    return dch->fd;
}

static inline int nflua_data_getpid(const struct nflua_data *dch)
{
    return dch->pid;
}

static inline int nflua_data_is_open(const struct nflua_data *dch)
{
    return dch->fd >= 0;
}

int nflua_data_init(struct nflua_data *dch, uint32_t pid);

void nflua_data_close(struct nflua_data *dch);

int nflua_data_send(struct nflua_data *dch, const char *name,
        const char *payload, size_t len);

int nflua_data_receive(struct nflua_data *dch, char *state, char *buffer);
#endif /* _UNUSED */
#endif /* LUNATIK_H */
