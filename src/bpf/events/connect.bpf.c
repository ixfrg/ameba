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


// local globals
static const record_type_t connect_record_type = RECORD_TYPE_CONNECT;
static const record_size_t connect_record_size = RECORD_SIZE_CONNECT;


// maps
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // TODO
    __type(key, struct map_key_process_record);
    __type(value, struct record_connect);
} process_record_map SEC(".maps");


static int is_connect_event_auditable(void)
{
    struct event_context e_ctx;
    event_context_init_event_context(&e_ctx, connect_record_type);
    return ameba_is_event_auditable(&e_ctx);
}

static int init_connect_map_key(struct map_key_process_record *map_key)
{
    if (!map_key)
        return 0;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    maphelper_init_map_key_process_record(map_key, pid, connect_record_type);
    return 0;
}

static int insert_connect_map_entry_at_syscall_enter(void)
{
    if (!is_connect_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_connect_map_key(&map_key);

    struct record_connect map_val;
    recordhelper_zero_out_record_connect(&map_val);
    long result = bpf_map_update_elem(&process_record_map, &map_key, (void *)&map_val, BPF_ANY);
    if (result != 0)
    {
        LOG_WARN("[insert_connect_map_entry_at_syscall_enter] Failed to do map insert. Error = %ld", result);
    }

    return 0;
}

static int delete_connect_map_entry(void)
{
    struct map_key_process_record map_key;
    init_connect_map_key(&map_key);

    bpf_map_delete_elem(&process_record_map, &map_key);

    return 0;
}

static int update_connect_map_entry_with_local_saddr(struct file *connect_sock_file)
{
    if (!is_connect_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_connect_map_key(&map_key);

    struct record_connect *map_val = bpf_map_lookup_elem(&process_record_map, &map_key);
    if (!map_val)
    {
        return 0;
    }

    struct socket *sock = bpf_sock_from_file(connect_sock_file);
    if (!sock)
    {
        delete_connect_map_entry();
        return 0;
    }

    struct sock_common sk_c = BPF_CORE_READ(sock, sk, __sk_common);
    switch (sk_c.skc_family)
    {
        case AF_INET:
            map_val->local.byte_order = BYTE_ORDER_HOST;
            map_val->local.addrlen = sizeof(struct sockaddr_in);
            struct sockaddr_in *sin = (struct sockaddr_in *)(&map_val->local.addr);
            sin->sin_family = sk_c.skc_family;
            sin->sin_port = sk_c.skc_num;
            sin->sin_addr.s_addr = sk_c.skc_rcv_saddr;
            break;
        case AF_INET6:
            map_val->local.byte_order = BYTE_ORDER_HOST;
            map_val->local.addrlen = sizeof(struct sockaddr_in6);
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(&map_val->local.addr);
            sin6->sin6_family = sk_c.skc_family;
            sin6->sin6_port = sk_c.skc_num;
            sin6->sin6_addr = sk_c.skc_v6_rcv_saddr;
            break;
        default:
            break;
    }

    return 0;
}

static int update_connect_map_entry_on_syscall_exit(
    int fd, struct sockaddr *addr, int addrlen, int ret
)
{
    if (!is_connect_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_connect_map_key(&map_key);

    struct record_connect *map_val = bpf_map_lookup_elem(&process_record_map, &map_key);
    if (!map_val)
        return 0;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    recordhelper_init_record_connect(map_val, pid, fd, ret);
    map_val->e_ts.event_id = ameba_increment_event_id();

    struct elem_sockaddr *remote_sa = (struct elem_sockaddr *)&(map_val->remote);
    remote_sa->byte_order = BYTE_ORDER_NETWORK;
    remote_sa->addrlen = addrlen & (SOCKADDR_MAX_SIZE - 1);
    bpf_probe_read_user(&(remote_sa->addr[0]), remote_sa->addrlen, addr);

    return 0;
}

static int send_connect_map_entry_on_syscall_exit(void)
{
    if (!is_connect_event_auditable())
        return 0;

    struct map_key_process_record map_key;
    init_connect_map_key(&map_key);

    struct record_connect *map_val = bpf_map_lookup_elem(&process_record_map, &map_key);
    if (!map_val)
        return 0;

    struct bpf_dynptr ptr;
    long dynptr_result = bpf_dynptr_from_mem(map_val, connect_record_size, 0, &ptr);
    if (dynptr_result == 0){
        ameba_write_record_to_output_buffer(&ptr, connect_record_type);
    } else {
        LOG_WARN("[send_connect_map_entry_on_syscall_exit] Failed to create dynptr for record. Error = %ld", dynptr_result);
    }

    return 0;
}

// hooks
SEC("fentry/__sys_connect")
int BPF_PROG(
    fentry__sys_connect,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen
)
{
    return insert_connect_map_entry_at_syscall_enter();
}

SEC("fexit/__sys_connect")
int BPF_PROG(
    fexit__sys_connect,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen,
    int ret
)
{
    if (ret != 0 && ret != ERROR_EINPROGRESS)
    {
        delete_connect_map_entry();
        return 0;
    }

    update_connect_map_entry_on_syscall_exit(fd, sockaddr, addrlen, ret);

    send_connect_map_entry_on_syscall_exit();

    delete_connect_map_entry();

    return 0;
}

struct sockaddr_storage;
SEC("fexit/__sys_connect_file")
int BPF_PROG(
    fexit__sys_connect_file,
    struct file *file,
    struct sockaddr_storage *address,
    int addrlen,
    int file_flags,
    int ret
)
{
    if (ret != 0 && ret != ERROR_EINPROGRESS)
    {
        delete_connect_map_entry();
        return 0;
    }

    update_connect_map_entry_with_local_saddr(file);

    return 0;
}

// static u16 local_ntohs(u16 netshort) {
//     return (netshort >> 8) | (netshort << 8);
// }

// SEC("fmod_ret/__arm64_sys_connect")
// int BPF_PROG(
//     fmod_ret__arm64_sys_connect
// )
// {
//     //bpf_override_return() kprobe
//     //__weak
//     if (!is_event_auditable(connect_record_type))
//         return 0;

//     struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

//     int fd;
//     struct sockaddr *addr;
//     int addrlen;

//     fd = (int)PT_REGS_PARM1(regs);
//     addr = (struct sockaddr *)PT_REGS_PARM2(regs);
//     addrlen = (int)PT_REGS_PARM3(regs);

//     // LOG_WARN("[fmod_ret__arm64_sys_connect] fd=%d", fd);
//     // LOG_WARN("[fmod_ret__arm64_sys_connect] addr=%p", addr);
//     // LOG_WARN("[fmod_ret__arm64_sys_connect] addrlen=%d", addrlen);

//     if (addr != NULL) {

//         struct elem_sockaddr e_sa;
//         e_sa.addrlen = addrlen & (SOCKADDR_MAX_SIZE - 1);
//         bpf_probe_read_user(&(e_sa.addr[0]), e_sa.addrlen, addr);

//         struct sockaddr *xaddr = (struct sockaddr *)e_sa.addr;

//         unsigned short sa_family = xaddr->sa_family;
//         // LOG_WARN("[fmod_ret__arm64_sys_connect] sa_family=%u", sa_family);
//         if (sa_family == AF_INET)
//         {
//             struct sockaddr_in *sin = (struct sockaddr_in *)xaddr;
//             u16 port = local_ntohs(sin->sin_port);
//             // LOG_WARN("[fmod_ret__arm64_sys_connect] port=%u", port);
//             if (port == 5689)
//             {
//                 // return -13; // EACCESS
//                 // return -1; // EPERM
//                 // return -22; // EINVAL
//                 return 0;
//             }
//         }
//     }

//     return 0;
// }