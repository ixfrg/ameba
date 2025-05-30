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


// local globals
static const record_type_t send_recv_record_type = RECORD_TYPE_SEND_RECV;


// maps
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAPS_HASH_MAP_MAX_ENTRIES); // TODO
    __type(key, struct map_key_process_record);
    __type(value, struct record_send_recv);
} process_record_map_send_recv SEC(".maps");


static int is_send_recv_event_auditable(void)
{
    struct event_context e_ctx;
    event_context_init_event_context(&e_ctx, RECORD_TYPE_SEND_RECV);
    return ameba_is_event_auditable(&e_ctx);
}

static int init_send_recv_map_key(struct map_key_process_record *map_key)
{
    if (!map_key)
        return 0;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    maphelper_init_map_key_process_record(map_key, pid, send_recv_record_type);
    return 0;
}

static int insert_send_recv_map_entry_at_syscall_enter(sys_id_t sys_id)
{
    if (!is_send_recv_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_send_recv_map_key(&map_key);

    struct record_send_recv map_val;
    recordhelper_zero_out_record_send_recv(&map_val);
    map_val.sys_id = sys_id;
    long result = bpf_map_update_elem(&process_record_map_send_recv, &map_key, (void *)&map_val, BPF_ANY);
    if (result != 0)
    {
        LOG_WARN("[insert_send_recv_map_entry_at_syscall_enter] Failed to do map insert. Error = %ld", result);
    }

    return 0;
}

static int delete_send_recv_map_entry(void)
{
    struct map_key_process_record map_key;
    init_send_recv_map_key(&map_key);

    bpf_map_delete_elem(&process_record_map_send_recv, &map_key);

    return 0;
}

static int update_send_recv_map_entry_with_local_saddr(struct socket *sock)
{
    if (!is_send_recv_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_send_recv_map_key(&map_key);

    struct record_send_recv *map_val = bpf_map_lookup_elem(&process_record_map_send_recv, &map_key);
    if (!map_val)
    {
        return 0;
    }

    if (!sock)
    {
        delete_send_recv_map_entry();
        return 0;
    }

    struct sock_common sk_c = BPF_CORE_READ(sock, sk, __sk_common);
    if (sk_c.skc_family == AF_INET) {
        data_copy_sockaddr_in_local_from_skc(&(map_val->local), &sk_c);
        data_copy_sockaddr_in_remote_from_skc(&(map_val->remote), &sk_c);
    } else if (sk_c.skc_family == AF_INET6) {
        data_copy_sockaddr_in6_local_from_skc(&(map_val->local), &sk_c);
        data_copy_sockaddr_in6_remote_from_skc(&(map_val->remote), &sk_c);
    }

    return 0;
}

static int update_send_recv_map_entry_on_syscall_exit(
    int fd, struct sockaddr *addr, int addrlen, ssize_t ret
)
{
    if (!is_send_recv_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_send_recv_map_key(&map_key);

    struct record_send_recv *map_val = bpf_map_lookup_elem(&process_record_map_send_recv, &map_key);
    if (!map_val)
        return 0;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    recordhelper_init_record_send_recv(map_val, pid, fd, ret);
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

static int send_send_recv_map_entry_on_syscall_exit(void)
{
    if (!is_send_recv_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_send_recv_map_key(&map_key);

    struct record_send_recv *map_val = bpf_map_lookup_elem(&process_record_map_send_recv, &map_key);
    if (!map_val)
        return 0;

    ameba_write_record_send_recv_to_output_buffer(map_val);

    return 0;
}

// Begin syscall sys_sendto 
// hooks
SEC("fentry/__sys_sendto")
int BPF_PROG(
    fentry__sys_sendto
)
{
    return insert_send_recv_map_entry_at_syscall_enter(SYS_ID_SENDTO);
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
        delete_send_recv_map_entry();
        return 0;
    }
    update_send_recv_map_entry_on_syscall_exit(fd, addr, addr_len, ret);
    send_send_recv_map_entry_on_syscall_exit();
    delete_send_recv_map_entry();
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
    return insert_send_recv_map_entry_at_syscall_enter(SYS_ID_SENDMSG);
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
        delete_send_recv_map_entry();
        return 0;
    }

    struct sockaddr *addr = NULL;
    int addrlen = 0;
    if (msg)
    {
        addr = (struct sockaddr *)BPF_CORE_READ(msg, msg_name);
        addrlen = BPF_CORE_READ(msg, msg_namelen);
    }
    update_send_recv_map_entry_on_syscall_exit(fd, addr, addrlen, ret);
    send_send_recv_map_entry_on_syscall_exit();
    delete_send_recv_map_entry();
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
        delete_send_recv_map_entry();
        return 0;
    }

    update_send_recv_map_entry_with_local_saddr(sock);

    return 0;
}