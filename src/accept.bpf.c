#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "record.h"


struct map_key_process_record_accept
{
    struct map_key_process_record map_key;
    int fd_type;
};


extern int is_event_auditable(void);
extern long write_record_to_output_buffer(struct bpf_dynptr *ptr, int record_type);
extern unsigned long increment_event_id(void);
extern long init_map_key_process_record(struct map_key_process_record *map_key, const int record_type_id);


struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // TODO
    __type(key, struct map_key_process_record_accept);
    __type(value, struct record_accept);
} process_record_map_accept SEC(".maps");


//

static long init_map_key_process_record_accept(
    struct map_key_process_record_accept *map_key, const int record_type_id, unsigned char fd_type
){
    init_map_key_process_record(&(map_key->map_key), record_type_id);
    map_key->fd_type = fd_type;
    return 0;
}


static long set_process_record_map_accept_key_val(
    unsigned char fd_type
)
{
    struct map_key_process_record_accept map_key;
    init_map_key_process_record_accept(&map_key, RECORD_TYPE_ACCEPT, fd_type);

    struct record_accept map_val;
    map_val.e_common.record_type_id = RECORD_TYPE_ACCEPT;
    map_val.local.addrlen = 0;
    map_val.remote.addrlen = 0;
    long result = bpf_map_update_elem(&process_record_map_accept, &map_key, (void *)&map_val, BPF_ANY);
    if (result != 0)
    {
        LOG_WARN("[enter__sys_accept4] Failed to update map for fd type: %u. Error = %ld", fd_type, result);
    }
    return 0;
}


static long set_internal_and_external_sockaddr_for_file(
    unsigned char fd_type,
    struct file *file
)
{
    struct map_key_process_record_accept map_key;
    init_map_key_process_record_accept(&map_key, RECORD_TYPE_ACCEPT, fd_type);

    if (file == NULL)
    {
        bpf_map_delete_elem(&process_record_map_accept, &map_key);
        return 0;
    }

    struct record_accept *map_val = bpf_map_lookup_elem(&process_record_map_accept, &map_key);
    if (map_val == NULL)
    {
        return 0;
    }

    struct socket *sock = bpf_sock_from_file(file);
    if (sock) {
        struct sock_common sk_c = BPF_CORE_READ(sock, sk, __sk_common);
        if (sk_c.skc_family == AF_INET) {
            // local
            map_val->local.addrlen = sizeof(struct sockaddr_in);
            struct sockaddr_in *sin_local = (struct sockaddr_in *)(&map_val->local.addr);
            sin_local->sin_family = sk_c.skc_family;
            sin_local->sin_port = sk_c.skc_num;
            sin_local->sin_addr.s_addr = sk_c.skc_rcv_saddr;

            // remote
            map_val->remote.addrlen = sizeof(struct sockaddr_in);
            struct sockaddr_in *sin_remote = (struct sockaddr_in *)(&map_val->remote.addr);
            sin_remote->sin_family = sk_c.skc_family;
            sin_remote->sin_port = sk_c.skc_dport;
            sin_remote->sin_addr.s_addr = sk_c.skc_daddr;
        } else if (sk_c.skc_family == AF_INET6) {
            // local
            map_val->local.addrlen = sizeof(struct sockaddr_in6);
            struct sockaddr_in6 *sin6_local = (struct sockaddr_in6 *)(&map_val->local.addr);
            sin6_local->sin6_family = sk_c.skc_family;
            sin6_local->sin6_port = sk_c.skc_num;
            sin6_local->sin6_addr = sk_c.skc_v6_rcv_saddr;

            // remote
            map_val->remote.addrlen = sizeof(struct sockaddr_in6);
            struct sockaddr_in6 *sin6_remote = (struct sockaddr_in6 *)(&map_val->remote.addr);
            sin6_remote->sin6_family = sk_c.skc_family;
            sin6_remote->sin6_port = sk_c.skc_dport;
            sin6_remote->sin6_addr = sk_c.skc_v6_daddr;
        }
    }
    return 0;
}

SEC("fentry/__sys_accept4")
int BPF_PROG(
    enter__sys_accept4,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen,
    int flags
)
{
    if (!is_event_auditable())
        return 0;

    set_process_record_map_accept_key_val(RECORD_ACCEPT_FD_TYPE_SERVER);
    set_process_record_map_accept_key_val(RECORD_ACCEPT_FD_TYPE_CLIENT);

    return 0;
}

struct proto_accept_arg;
SEC("fexit/do_accept")
int BPF_PROG(
    exit__do_accept,
    struct file *file,
    struct proto_accept_arg *arg,
	struct sockaddr *upeer_sockaddr,
	int *upeer_addrlen,
    int flags,
    struct file *ret_file
)
{
    if (!is_event_auditable())
        return 0;

    if (ret_file == NULL){
        return 0;
    }

    set_internal_and_external_sockaddr_for_file(RECORD_ACCEPT_FD_TYPE_SERVER, file);
    set_internal_and_external_sockaddr_for_file(RECORD_ACCEPT_FD_TYPE_CLIENT, ret_file);

    return 0;
}


SEC("fexit/__sys_accept4")
int BPF_PROG(
    exit__sys_accept4,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen,
    int flags,
    int ret
)
{
    if (!is_event_auditable())
        goto exit;

    struct map_key_process_record_accept map_key_server;
    init_map_key_process_record_accept(&map_key_server, RECORD_TYPE_ACCEPT, RECORD_ACCEPT_FD_TYPE_SERVER);

    struct map_key_process_record_accept map_key_client;
    init_map_key_process_record_accept(&map_key_client, RECORD_TYPE_ACCEPT, RECORD_ACCEPT_FD_TYPE_CLIENT);

    if (ret == -1)
    {
        goto delete_map_entries;
    }

    struct record_accept *map_val_server = bpf_map_lookup_elem(&process_record_map_accept, &map_key_server);
    if (map_val_server == NULL)
    {
        goto delete_map_entries;
    }

    struct record_accept *map_val_client = bpf_map_lookup_elem(&process_record_map_accept, &map_key_client);
    if (map_val_client == NULL)
    {
        goto delete_map_entries;
    }

    unsigned long event_id = increment_event_id();

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    map_val_server->fd = fd;
    map_val_server->fd_type = map_key_server.fd_type;
    map_val_server->pid = pid;
    map_val_server->e_common.event_id = event_id;

    map_val_client->fd = ret;
    map_val_client->fd_type = map_key_client.fd_type;
    map_val_client->pid = pid;
    map_val_client->e_common.event_id = event_id;

    struct bpf_dynptr ptr_server;
    long dynptr_result_server = bpf_dynptr_from_mem(map_val_server, RECORD_SIZE_ACCEPT, 0, &ptr_server);
    if (dynptr_result_server == 0){
        write_record_to_output_buffer(&ptr_server, RECORD_TYPE_ACCEPT);
    } else {
        LOG_WARN("[exit__sys_accept4] Failed to create server dynptr for record. Error = %ld", dynptr_result_server);
    }

    struct bpf_dynptr ptr_client;
    long dynptr_result_client = bpf_dynptr_from_mem(map_val_client, RECORD_SIZE_ACCEPT, 0, &ptr_client);
    if (dynptr_result_client == 0){
        write_record_to_output_buffer(&ptr_client, RECORD_TYPE_ACCEPT);
    } else {
        LOG_WARN("[exit__sys_accept4] Failed to create client dynptr for record. Error = %ld", dynptr_result_client);
    }

delete_map_entries:
    bpf_map_delete_elem(&process_record_map_accept, &map_key_server);
    bpf_map_delete_elem(&process_record_map_accept, &map_key_client);

exit:
    return 0;
}