
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>

int sock_init = 0;


int *(*parent_socket)(int domain, int type, int protocol);

int socket(int domain, int type, int protocol)
{
    printf("In our own socket\n");
    parent_socket = dlsym(RTLD_NEXT, "socket");
    return (*parent_socket)(domain, type, protocol);
}