#include "common/vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common/types.h"
#include "bpf/helpers/log.bpf.h"
#include "bpf/helpers/event_id.bpf.h"
#include "bpf/helpers/event.bpf.h"
#include "bpf/helpers/datatype.bpf.h"
#include "bpf/helpers/copy.bpf.h"
#include "bpf/helpers/output.bpf.h"
#include "bpf/events/connect/storage.bpf.h"


// local globals
static const record_type_t connect_record_type = RECORD_TYPE_CONNECT;
// static const record_size_t connect_record_size = RECORD_SIZE_CONNECT;


static int insert_connect_map_entry_at_syscall_enter(void)
{
    struct record_connect map_val;
    datatype_zero_out_record_connect(&map_val);
    int result = connect_storage_insert(&map_val);
    if (result != 0)
    {
        LOG_WARN("[insert_connect_map_entry_at_syscall_enter] Failed to do map insert. Error = %ld", result);
    }

    return 0;
}

static int delete_connect_map_entry(void)
{
    connect_storage_delete();

    return 0;
}

static int update_connect_map_entry_with_local_saddr(struct file *connect_sock_file)
{
    struct socket *sock = bpf_sock_from_file(connect_sock_file);
    if (!sock)
    {
        delete_connect_map_entry();
        return 0;
    }

    int local_is_set = 0;
    struct elem_sockaddr local;

    struct sock_common sk_c = BPF_CORE_READ(sock, sk, __sk_common);
    switch (sk_c.skc_family)
    {
        case AF_INET:
            copy_sockaddr_in_local_from_skc(&local, &sk_c);
            local_is_set = 1;
            break;
        case AF_INET6:
            copy_sockaddr_in6_local_from_skc(&local, &sk_c);
            local_is_set = 1;
            break;
        default:
            break;
    }

    if (local_is_set)
        connect_storage_set_local(&local);

    return 0;
}

static int update_connect_map_entry_on_syscall_exit(
    int fd, struct sockaddr *addr, int addrlen, int ret
)
{
    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    connect_storage_set_props_on_sys_exit(pid, fd, ret, event_id_increment());

    struct elem_sockaddr remote;
    remote.byte_order = BYTE_ORDER_NETWORK;
    remote.addrlen = addrlen & (SOCKADDR_MAX_SIZE - 1);
    bpf_probe_read_user(&(remote.addr[0]), remote.addrlen, addr);
    connect_storage_set_remote(&remote);

    return 0;
}

static int send_connect_map_entry_on_syscall_exit(void)
{
    connect_storage_output();

    return 0;
}

// hooks
int AMEBA_HOOK(
    "fentry/__sys_connect",
    fentry__sys_connect,
    connect_record_type,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen
)
{
    insert_connect_map_entry_at_syscall_enter();
    return 0;
}

int AMEBA_HOOK(
    "fexit/__sys_connect",
    fexit__sys_connect,
    connect_record_type,
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
int AMEBA_HOOK(
    "fexit/__sys_connect_file",
    fexit__sys_connect_file,
    connect_record_type,
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