#include "common/vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common/types.h"
#include "bpf/helpers/log.bpf.h"
#include "bpf/maps/map.bpf.h"
#include "bpf/helpers/event_context.bpf.h"
#include "bpf/helpers/record_helper.bpf.h"
#include "bpf/ameba.bpf.h"
#include "bpf/maps/constants.h"
#include "bpf/helpers/data_copy.bpf.h"
#include "bpf/helpers/output.bpf.h"


// local globals
static const record_type_t bind_record_type = RECORD_TYPE_BIND;
// static const record_size_t bind_record_size = RECORD_SIZE_BIND;

/*
// maps
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAPS_HASH_MAP_MAX_ENTRIES); // TODO
    __type(key, struct map_key_process_record);
    __type(value, struct record_bind);
} process_record_map_bind SEC(".maps");
*/

static int is_bind_event_auditable(void)
{
    struct event_context e_ctx;
    event_context_init_event_context(&e_ctx, bind_record_type);
    return ameba_is_event_auditable(&e_ctx);
}
/*
static int init_bind_map_key(struct map_key_process_record *map_key)
{
    if (!map_key)
        return 0;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    maphelper_init_map_key_process_record(map_key, pid, bind_record_type);
    return 0;
}
*/
/*
static int insert_bind_map_entry_at_syscall_enter(void)
{
    if (!is_bind_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_bind_map_key(&map_key);

    struct record_bind map_val;
    recordhelper_zero_out_record_bind(&map_val);
    long result = bpf_map_update_elem(&process_record_map_bind, &map_key, (void *)&map_val, BPF_ANY);
    if (result != 0)
    {
        LOG_WARN("[insert_bind_map_entry_at_syscall_enter] Failed to do map insert. Error = %ld", result);
    }

    return 0;
}
*/
/*
static int delete_bind_map_entry(void)
{
    struct map_key_process_record map_key;
    init_bind_map_key(&map_key);

    bpf_map_delete_elem(&process_record_map_bind, &map_key);

    return 0;
}
*/
/*
static int update_bind_map_entry_with_local_saddr(struct socket *sock)
{
    if (!is_bind_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_bind_map_key(&map_key);

    struct record_bind *map_val = bpf_map_lookup_elem(&process_record_map_bind, &map_key);
    if (!map_val)
    {
        return 0;
    }

    if (!sock)
    {
        delete_bind_map_entry();
        return 0;
    }

    struct sock_common sk_c = BPF_CORE_READ(sock, sk, __sk_common);
    switch (sk_c.skc_family)
    {
        case AF_INET:
            data_copy_sockaddr_in_local_from_skc(&(map_val->local), &sk_c);
            break;
        case AF_INET6:
            data_copy_sockaddr_in6_local_from_skc(&(map_val->local), &sk_c);
            break;
        default:
            break;
    }

    return 0;
}
*/
/*
static int update_bind_map_entry_on_syscall_exit(
    int fd, struct sockaddr *addr, int addrlen
)
{
    if (!is_bind_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_bind_map_key(&map_key);

    struct record_bind *map_val = bpf_map_lookup_elem(&process_record_map_bind, &map_key);
    if (!map_val)
        return 0;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    recordhelper_init_record_bind(map_val, pid, fd);
    map_val->e_ts.event_id = ameba_increment_event_id();

    struct elem_sockaddr *remote_sa = (struct elem_sockaddr *)&(map_val->remote);
    remote_sa->byte_order = BYTE_ORDER_NETWORK;
    remote_sa->addrlen = addrlen & (SOCKADDR_MAX_SIZE - 1);
    bpf_probe_read_user(&(remote_sa->addr[0]), remote_sa->addrlen, addr);

    return 0;
}
*/
/*
static int send_bind_map_entry_on_syscall_exit(void)
{
    if (!is_bind_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_bind_map_key(&map_key);

    struct record_bind *map_val = bpf_map_lookup_elem(&process_record_map_bind, &map_key);
    if (!map_val)
        return 0;

    ameba_write_record_bind_to_output_buffer(map_val);

    return 0;
}
*/
/*
// hooks
SEC("fentry/__sys_bind")
int BPF_PROG(
    fentry__sys_bind,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen
)
{
    return insert_bind_map_entry_at_syscall_enter();
}
*/
/*
SEC("fexit/__sys_bind")
int BPF_PROG(
    fexit__sys_bind,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen,
    int ret
)
{
    if (ret == -1)
    {
        delete_bind_map_entry();
        return 0;
    }

    update_bind_map_entry_on_syscall_exit(fd, sockaddr, addrlen);

    send_bind_map_entry_on_syscall_exit();

    delete_bind_map_entry();

    return 0;
}
*/
/*
SEC("fexit/inet_bind")
int BPF_PROG(
    fexit__inet_bind,
    struct socket *sock, 
    struct sockaddr *uaddr, 
    int addr_len,
    int ret
)
{
    if (ret == -1)
    {
        delete_bind_map_entry();
        return 0;
    }

    update_bind_map_entry_with_local_saddr(sock);

    return 0;
}

SEC("fexit/inet6_bind")
int BPF_PROG(
    fexit__inet6_bind,
    struct socket *sock, 
    struct sockaddr *uaddr, 
    int addr_len,
    int ret
)
{
    if (ret == -1)
    {
        delete_bind_map_entry();
        return 0;
    }

    update_bind_map_entry_with_local_saddr(sock);

    return 0;
}
*/

SEC("fexit/__sys_bind")
int BPF_PROG(
    fexit__sys_bind,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen,
    int ret
)
{
    if (ret == -1)
    {
        return 0;
    }

    if (!is_bind_event_auditable())
        return 0;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    struct record_bind r_bind;
    recordhelper_init_record_bind(&r_bind, pid, fd);
    r_bind.e_ts.event_id = ameba_increment_event_id();

    struct elem_sockaddr *local_sa = (struct elem_sockaddr *)&(r_bind.local);
    local_sa->byte_order = BYTE_ORDER_NETWORK;
    local_sa->addrlen = addrlen & (SOCKADDR_MAX_SIZE - 1);
    bpf_probe_read_user(&(local_sa->addr[0]), local_sa->addrlen, sockaddr);

    output_record_bind(&r_bind);

    return 0;
}