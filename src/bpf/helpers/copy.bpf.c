#include "bpf/helpers/copy.bpf.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>


int copy_sockaddr_in_local_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c)
{
    if (!dst || !sk_c)
        return 0;
    
    dst->byte_order = BYTE_ORDER_HOST;
    dst->addrlen = sizeof(struct sockaddr_in);

    struct sockaddr_in *sin = (struct sockaddr_in *)(&dst->addr);
    sin->sin_family = BPF_CORE_READ(sk_c, skc_family);
    sin->sin_port = BPF_CORE_READ(sk_c, skc_num);
    sin->sin_addr.s_addr = BPF_CORE_READ(sk_c, skc_rcv_saddr);

    return 0;
}

int copy_sockaddr_in_remote_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c)
{
    if (!dst || !sk_c)
        return 0;

    dst->byte_order = BYTE_ORDER_NETWORK;
    dst->addrlen = sizeof(struct sockaddr_in);

    struct sockaddr_in *sin = (struct sockaddr_in *)(&dst->addr);
    sin->sin_family = BPF_CORE_READ(sk_c, skc_family);
    sin->sin_port = BPF_CORE_READ(sk_c, skc_dport);
    sin->sin_addr.s_addr = BPF_CORE_READ(sk_c, skc_daddr);

    return 0;
}

int copy_sockaddr_in6_local_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c)
{
    if (!dst || !sk_c)
        return 0;

    dst->byte_order = BYTE_ORDER_HOST;
    dst->addrlen = sizeof(struct sockaddr_in6);

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(&dst->addr);
    sin6->sin6_family = BPF_CORE_READ(sk_c, skc_family);
    sin6->sin6_port = BPF_CORE_READ(sk_c, skc_num);
    sin6->sin6_addr = BPF_CORE_READ(sk_c, skc_v6_rcv_saddr);

    return 0;
}

int copy_sockaddr_in6_remote_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c)
{
    if (!dst || !sk_c)
        return 0;

    dst->byte_order = BYTE_ORDER_NETWORK;
    dst->addrlen = sizeof(struct sockaddr_in6);

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(&dst->addr);
    sin6->sin6_family = BPF_CORE_READ(sk_c, skc_family);
    sin6->sin6_port = BPF_CORE_READ(sk_c, skc_dport);
    sin6->sin6_addr = BPF_CORE_READ(sk_c, skc_v6_daddr);

    return 0;
}