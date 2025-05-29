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


// local globals
static const record_type_t send_record_type = RECORD_TYPE_SEND;


// maps
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAPS_HASH_MAP_MAX_ENTRIES); // TODO
    __type(key, struct map_key_process_record);
    __type(value, struct record_send);
} process_record_map_send SEC(".maps");


static int is_send_event_auditable(void)
{
    struct event_context e_ctx;
    event_context_init_event_context(&e_ctx, send_record_type);
    return ameba_is_event_auditable(&e_ctx);
}

static int init_send_map_key(struct map_key_process_record *map_key)
{
    if (!map_key)
        return 0;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    maphelper_init_map_key_process_record(map_key, pid, send_record_type);
    return 0;
}

static int insert_send_map_entry_at_syscall_enter(sys_id_t sys_id)
{
    if (!is_send_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_send_map_key(&map_key);

    struct record_send map_val;
    recordhelper_zero_out_record_send(&map_val);
    map_val.sys_id = sys_id;
    long result = bpf_map_update_elem(&process_record_map_send, &map_key, (void *)&map_val, BPF_ANY);
    if (result != 0)
    {
        LOG_WARN("[insert_send_map_entry_at_syscall_enter] Failed to do map insert. Error = %ld", result);
    }

    return 0;
}

static int delete_send_map_entry(void)
{
    struct map_key_process_record map_key;
    init_send_map_key(&map_key);

    bpf_map_delete_elem(&process_record_map_send, &map_key);

    return 0;
}

static int update_send_map_entry_with_local_saddr(struct socket *sock)
{
    if (!is_send_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_send_map_key(&map_key);

    struct record_send *map_val = bpf_map_lookup_elem(&process_record_map_send, &map_key);
    if (!map_val)
    {
        return 0;
    }

    if (!sock)
    {
        delete_send_map_entry();
        return 0;
    }

    struct sock_common sk_c = BPF_CORE_READ(sock, sk, __sk_common);
    if (sk_c.skc_family == AF_INET) {
        // local
        map_val->local.byte_order = BYTE_ORDER_HOST;
        map_val->local.addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in *sin_local = (struct sockaddr_in *)(&map_val->local.addr);
        sin_local->sin_family = sk_c.skc_family;
        sin_local->sin_port = sk_c.skc_num;
        sin_local->sin_addr.s_addr = sk_c.skc_rcv_saddr;

        // remote
        map_val->remote.byte_order = BYTE_ORDER_NETWORK;
        map_val->remote.addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in *sin_remote = (struct sockaddr_in *)(&map_val->remote.addr);
        sin_remote->sin_family = sk_c.skc_family;
        sin_remote->sin_port = sk_c.skc_dport;
        sin_remote->sin_addr.s_addr = sk_c.skc_daddr;
    } else if (sk_c.skc_family == AF_INET6) {
        // local
        map_val->local.byte_order = BYTE_ORDER_HOST;
        map_val->local.addrlen = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 *sin6_local = (struct sockaddr_in6 *)(&map_val->local.addr);
        sin6_local->sin6_family = sk_c.skc_family;
        sin6_local->sin6_port = sk_c.skc_num;
        sin6_local->sin6_addr = sk_c.skc_v6_rcv_saddr;

        // remote
        map_val->remote.byte_order = BYTE_ORDER_NETWORK;
        map_val->remote.addrlen = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 *sin6_remote = (struct sockaddr_in6 *)(&map_val->remote.addr);
        sin6_remote->sin6_family = sk_c.skc_family;
        sin6_remote->sin6_port = sk_c.skc_dport;
        sin6_remote->sin6_addr = sk_c.skc_v6_daddr;
    }

    return 0;
}

static int update_send_map_entry_on_syscall_exit(
    int fd, struct sockaddr *addr, int addrlen, ssize_t ret
)
{
    if (!is_send_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_send_map_key(&map_key);

    struct record_send *map_val = bpf_map_lookup_elem(&process_record_map_send, &map_key);
    if (!map_val)
        return 0;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    recordhelper_init_record_send(map_val, pid, fd, ret);
    map_val->e_ts.event_id = ameba_increment_event_id();

    if (addr)
    {
        // Sometimes NULL like in send/sendmsg syscall.
        struct elem_sockaddr *remote_sa = (struct elem_sockaddr *)&(map_val->remote);
        remote_sa->byte_order = BYTE_ORDER_NETWORK;
        remote_sa->addrlen = addrlen & (SOCKADDR_MAX_SIZE - 1);
        bpf_probe_read_user(&(remote_sa->addr[0]), remote_sa->addrlen, addr);
    }

    return 0;
}

static int send_send_map_entry_on_syscall_exit(void)
{
    if (!is_send_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_send_map_key(&map_key);

    struct record_send *map_val = bpf_map_lookup_elem(&process_record_map_send, &map_key);
    if (!map_val)
        return 0;

    ameba_write_record_send_to_output_buffer(map_val);

    return 0;
}

// Begin syscall sys_sendto 
// hooks
SEC("fentry/__sys_sendto")
int BPF_PROG(
    fentry__sys_sendto
)
{
    return insert_send_map_entry_at_syscall_enter(SYS_ID_SENDTO);
}

SEC("fexit/__sys_sendto")
int BPF_PROG(
    fexit__sys_sendto,
    int fd, 
    void *buff, 
    size_t len, 
    unsigned int flags,
	struct sockaddr *addr,
    int addr_len,
    ssize_t ret
)
{
    if (ret < 0)
    {
        delete_send_map_entry();
        return 0;
    }
    update_send_map_entry_on_syscall_exit(fd, addr, addr_len, ret);
    send_send_map_entry_on_syscall_exit();
    delete_send_map_entry();
    return 0;
}
// End syscall sys_sendto

// Begin syscall sys_sendmsg
// hooks
SEC("fentry/__sys_sendmsg")
int BPF_PROG(
    fentry__sys_sendmsg
)
{
    return insert_send_map_entry_at_syscall_enter(SYS_ID_SENDMSG);
}

SEC("fexit/__sys_sendmsg")
int BPF_PROG(
    fexit__sys_sendmsg,
    int fd, 
    struct user_msghdr *msg, 
    unsigned int flags,
	bool forbid_cmsg_compat,
    long ret
)
{
    if (ret < 0)
    {
        delete_send_map_entry();
        return 0;
    }
    update_send_map_entry_on_syscall_exit(fd, NULL, 0, ret);
    send_send_map_entry_on_syscall_exit();
    delete_send_map_entry();
    return 0;
}
// End syscall sys_sendmsg

// Intermediate state update function
SEC("fexit/__sock_sendmsg")
int BPF_PROG(
    fexit__sock_sendmsg,
    struct socket *sock,
    struct msghdr *msg,
    int ret
)
{
    if (ret < 0)
    {
        delete_send_map_entry();
        return 0;
    }

    update_send_map_entry_with_local_saddr(sock);

    return 0;
}