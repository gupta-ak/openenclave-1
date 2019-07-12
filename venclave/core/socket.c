// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "socket.h"
#include "common.h"
#include "syscall.h"

/* The socket for the current thread. */
static __thread int _sock = -1;

ssize_t ve_recvmsg(int sockfd, struct ve_msghdr* msg, int flags)
{
    long x1 = (long)sockfd;
    long x2 = (long)msg;
    long x3 = (long)flags;
    return (ssize_t)ve_syscall6(VE_SYS_recvmsg, x1, x2, x3, 0, 0, 0);
}

int ve_socketpair(int domain, int type, int protocol, int sv[2])
{
    return (int)ve_syscall4(
        VE_SYS_socketpair, domain, type, protocol, (long)sv);
}

void ve_set_sock(int sock)
{
    _sock = sock;
}

int ve_get_sock(void)
{
    return _sock;
}