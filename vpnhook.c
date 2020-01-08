
#define _GNU_SOURCE
#include "backbone.h"

#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/un.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int sock_init = 0;

#define SETSOCKOPT_SIG int fd, int level, int optname, const void *optval, socklen_t optlen
#define GETSOCKOPT_SIG int fd, int level, int optname, void *optval, socklen_t *optlen

#define SENDMSG_SIG int fd, const struct msghdr *msg, int flags

#define SENDTO_SIG int fd, const void *buf, size_t len, int flags, \
    const struct sockaddr *addr, socklen_t addrlen

#define RECV_SIG int fd, void *buf, size_t len, int flags
#define RECVFROM_SIG int fd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *addrlen
#define RECVMSG_SIG int fd, struct msghdr *msg,int flags

#define SEND_SIG int fd, const void *buf, size_t len, int flags
#define WRITE_SIG int fd, const void *buf, size_t len
#define READ_SIG int fd, void *buf, size_t len

#define SOCKET_SIG int socket_family, int socket_type, int protocol
#define CONNECT_SIG int fd, const struct sockaddr *addr, socklen_t addrlen
#define BIND_SIG int fd, const struct sockaddr *addr, socklen_t addrlen
#define LISTEN_SIG int fd, int backlog
#define ACCEPT4_SIG int fd, struct sockaddr *addr, socklen_t *addrlen, int flags
#define ACCEPT_SIG int fd, struct sockaddr *addr, socklen_t *addrlen
#define CLOSE_SIG int fd
#define GETSOCKNAME_SIG int fd, struct sockaddr *addr, socklen_t *addrlen
#define GETPEERNAME_SIG int fd, struct sockaddr *addr, socklen_t *addrlen
#define FCNTL_SIG int fd, int cmd, int flags
#define SYSCALL_SIG long number, ...


/* hooks */
int (*parent_socket)(SOCKET_SIG) = 0;
int (*parent_setsockopt )(SETSOCKOPT_SIG);
int (*parent_getsockopt )(GETSOCKOPT_SIG);
int (*parent_connect )(CONNECT_SIG);
int (*parent_accept )(ACCEPT_SIG);
int (*parent_listen )(LISTEN_SIG);
int (*parent_close )(CLOSE_SIG);
int (*parent_getsockname )(GETSOCKNAME_SIG);
int (*parent_bind )(BIND_SIG);
ssize_t (*parent_sendto )(SENDTO_SIG);
int (*parent_recvfrom )(RECVFROM_SIG);
int (* parent_recvmsg )(RECVMSG_SIG);



void init_hooks()
{
    in_addr_t ipaddr;
    const char *net_if;

    parent_socket = (int(*)(SOCKET_SIG))dlsym(RTLD_NEXT, "socket");
    parent_setsockopt = (int(*)(SETSOCKOPT_SIG))dlsym(RTLD_NEXT, "setsockopt");
    parent_getsockopt = (int(*)(GETSOCKOPT_SIG))dlsym(RTLD_NEXT, "getsockopt");
    parent_socket = (int(*)(SOCKET_SIG))dlsym(RTLD_NEXT, "socket");
    parent_connect = (int(*)(CONNECT_SIG))dlsym(RTLD_NEXT, "connect");
    parent_accept = (int(*)(ACCEPT_SIG))dlsym(RTLD_NEXT, "accept");
    parent_listen = (int(*)(LISTEN_SIG))dlsym(RTLD_NEXT, "listen");
    parent_close = (int(*)(CLOSE_SIG))dlsym(RTLD_NEXT, "close");
    parent_getsockname = (int(*)(GETSOCKNAME_SIG))dlsym(RTLD_NEXT, "getsockname");
    parent_bind = (int(*)(BIND_SIG))dlsym(RTLD_NEXT, "bind");
    parent_sendto = (ssize_t(*)(SENDTO_SIG))dlsym(RTLD_NEXT, "sendto");
    parent_recvfrom = (int(*)(RECVFROM_SIG))dlsym(RTLD_NEXT, "recvfrom");
    parent_recvmsg = (int(*)(RECVMSG_SIG))dlsym(RTLD_NEXT, "recvmsg");

    net_if = getenv("ETH0_ADDR");

    ipaddr = inet_addr(net_if);
    udp_backbone.ip_stack_init(ipaddr);


    sock_init = 1;
}
int socket(SOCKET_SIG)
{
    printf("In our own socket\n");
    if (sock_init == 0) {
        init_hooks();
    }
    // if it's not something we care about
    if (socket_family != AF_INET || socket_type != SOCK_DGRAM || socket_type != SOCK_STREAM)
        return (*parent_socket)(socket_family, socket_type, protocol);

    //

}
