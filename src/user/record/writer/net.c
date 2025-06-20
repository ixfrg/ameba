#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "user/record/writer/writer.h"
#include "user/types.h"


static struct {
    int sockfd;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int initialized;
    struct output_net init_args;
} state = {0};


static int set_init_args_net(void *ptr, size_t ptr_len) {
    if (ptr_len != sizeof(struct output_net))
        return -1;

    struct output_net *in = (struct output_net *)ptr;

    if (in->ip_family == AF_INET)
    {
        if (inet_pton(AF_INET, &(in->ip[0]), &( (struct sockaddr_in *)&state.addr )->sin_addr)) {
            struct sockaddr_in *addr4 = (struct sockaddr_in *)&state.addr;
            addr4->sin_family = AF_INET;
            addr4->sin_port = htons(in->port);
            state.addr_len = sizeof(struct sockaddr_in);
        } else {
            return -1;
        }
    } else if (in->ip_family == AF_INET6)
    {
        if (inet_pton(AF_INET6, &(in->ip[0]), &( (struct sockaddr_in6 *)&state.addr )->sin6_addr)) {
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&state.addr;
            addr6->sin6_family = AF_INET6;
            addr6->sin6_port = htons(in->port);
            state.addr_len = sizeof(struct sockaddr_in6);
        } else {
            return -1;
        }
    } else {
        return -2;
    }

    memcpy(&state.init_args, in, sizeof(struct output_net));
    return 0;
}

static int init_net() {
    if (state.initialized) return 0;

    state.sockfd = socket(((struct sockaddr *)&state.addr)->sa_family, SOCK_DGRAM, 0);
    if (state.sockfd < 0)
        return -1;

    state.initialized = 1;
    return 0;
}

static int close_net() {
    if (state.initialized) {
        close(state.sockfd);
        state.initialized = 0;
    }
    return 0;
}

static int write_net(void *data, size_t data_len) {
    if (!state.initialized)
        return -2;

    ssize_t sent = sendto(state.sockfd, data, data_len, 0,
                          (struct sockaddr *)&state.addr, state.addr_len);
    if (sent < 0)
        return -1;

    return (int)sent;
}

const struct record_writer record_writer_net = {
    .set_init_args = set_init_args_net,
    .init = init_net,
    .close = close_net,
    .write = write_net,
};