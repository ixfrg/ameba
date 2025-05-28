#include "common/vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common/types.h"
#include "kernel/helpers/log.bpf.h"
#include "kernel/maps/map.bpf.h"
#include "kernel/helpers/event_context.bpf.h"


// defs
typedef enum {
    LOCAL = 1,
    REMOTE = 2
} accept_type_fd_t;


struct map_key_process_record_accept
{
    struct map_key_process_record map_key;
    accept_type_fd_t fd_type;
};


// local globals
static const record_type_t accept_record_type = RECORD_TYPE_ACCEPT;


// maps
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // TODO
    __type(key, struct map_key_process_record_accept);
    __type(value, struct record_accept);
} process_record_map_accept SEC(".maps");


// externs
extern int recordhelper_zero_out_record_accept(
    struct record_accept *r_accept
);
extern int recordhelper_init_record_accept(
    struct record_accept *r_accept,
    pid_t pid, int fd
);
extern int recordhelper_zero_out_elem_sockaddr(
    struct elem_sockaddr *e_sockaddr
);
extern int recordhelper_init_elem_sockaddr(
    struct elem_sockaddr *e_sockaddr,
    socklen_t addrlen,
    byte_order_t byte_order
);
extern event_id_t ameba_increment_event_id(void);
extern int ameba_is_event_auditable(struct event_context *e_ctx);
extern long ameba_write_record_to_output_buffer(struct bpf_dynptr *ptr, record_type_t record_type);


// local functions
static int init_map_key_process_record_accept(
    struct map_key_process_record_accept *map_key, 
    pid_t pid, const record_type_t record_type, accept_type_fd_t fd_type
){
    if (!map_key)
        return 0;
    maphelper_init_map_key_process_record(&(map_key->map_key), pid, record_type);
    map_key->fd_type = fd_type;
    return 0;
}


static long set_process_record_map_accept_key_val(
    pid_t pid, accept_type_fd_t fd_type
)
{
    struct map_key_process_record_accept map_key;
    init_map_key_process_record_accept(&map_key, pid, accept_record_type, fd_type);

    struct record_accept map_val;
    recordhelper_zero_out_record_accept(&map_val);
    long result = bpf_map_update_elem(&process_record_map_accept, &map_key, (void *)&map_val, BPF_ANY);
    if (result != 0)
    {
        LOG_WARN("[fentry__sys_accept4] Failed to update map for fd type: %u. Error = %ld", fd_type, result);
    }
    return 0;
}


static long set_internal_and_external_sockaddr_for_file(
    pid_t pid, struct file *file, accept_type_fd_t fd_type
)
{
    struct map_key_process_record_accept map_key;
    init_map_key_process_record_accept(&map_key, pid, accept_record_type, fd_type);

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
    fentry__sys_accept4,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen,
    int flags
)
{
    struct event_context e_ctx;
    event_context_init_event_context(&e_ctx, accept_record_type);

    if (!ameba_is_event_auditable(&e_ctx))
        return 0;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    set_process_record_map_accept_key_val(pid, LOCAL);
    set_process_record_map_accept_key_val(pid, REMOTE);

    return 0;
}

struct proto_accept_arg;
SEC("fexit/do_accept")
int BPF_PROG(
    fexit__do_accept,
    struct file *file,
    struct proto_accept_arg *arg,
	struct sockaddr *upeer_sockaddr,
	int *upeer_addrlen,
    int flags,
    struct file *ret_file
)
{
    struct event_context e_ctx;
    event_context_init_event_context(&e_ctx, accept_record_type);

    if (!ameba_is_event_auditable(&e_ctx))
        return 0;

    if (ret_file == NULL){
        return 0;
    }

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    set_internal_and_external_sockaddr_for_file(pid, file, LOCAL);
    set_internal_and_external_sockaddr_for_file(pid, ret_file, REMOTE);

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
    struct event_context e_ctx;
    event_context_init_event_context(&e_ctx, accept_record_type);

    if (!ameba_is_event_auditable(&e_ctx))
        goto exit;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    struct map_key_process_record_accept map_key_server;
    init_map_key_process_record_accept(&map_key_server, pid, accept_record_type, LOCAL);

    struct map_key_process_record_accept map_key_client;
    init_map_key_process_record_accept(&map_key_client, pid, accept_record_type, REMOTE);

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

    event_id_t event_id = ameba_increment_event_id();

    map_val_server->fd = fd;
    map_val_server->pid = pid;
    map_val_server->e_ts.event_id = event_id;

    map_val_client->fd = ret;
    map_val_client->pid = pid;
    map_val_client->e_ts.event_id = event_id;

    struct bpf_dynptr ptr_server;
    long dynptr_result_server = bpf_dynptr_from_mem(map_val_server, RECORD_SIZE_ACCEPT, 0, &ptr_server);
    if (dynptr_result_server == 0){
        ameba_write_record_to_output_buffer(&ptr_server, accept_record_type);
    } else {
        LOG_WARN("[fexit__sys_accept4] Failed to create server dynptr for record. Error = %ld", dynptr_result_server);
    }

    struct bpf_dynptr ptr_client;
    long dynptr_result_client = bpf_dynptr_from_mem(map_val_client, RECORD_SIZE_ACCEPT, 0, &ptr_client);
    if (dynptr_result_client == 0){
        ameba_write_record_to_output_buffer(&ptr_client, accept_record_type);
    } else {
        LOG_WARN("[fexit__sys_accept4] Failed to create client dynptr for record. Error = %ld", dynptr_result_client);
    }

delete_map_entries:
    bpf_map_delete_elem(&process_record_map_accept, &map_key_server);
    bpf_map_delete_elem(&process_record_map_accept, &map_key_client);

exit:
    return 0;
}