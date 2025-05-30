#include "common/vmlinux.h"
#include "common/types.h"


int data_copy_sockaddr_in_local_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c);
int data_copy_sockaddr_in_remote_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c);
int data_copy_sockaddr_in6_local_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c);
int data_copy_sockaddr_in6_remote_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c);