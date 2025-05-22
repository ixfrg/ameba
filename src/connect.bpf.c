#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "record.h"


extern int is_event_auditable(int record_type);
extern long write_record_to_output_buffer(struct bpf_dynptr *ptr, int record_type);
extern unsigned long increment_event_id(void);
extern long init_map_key_process_record(struct map_key_process_record *map_key, const int record_type_id);


struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // TODO
    __type(key, struct map_key_process_record);
    __type(value, struct record_connect);
} process_record_map SEC(".maps");


//

SEC("fentry/__sys_connect")
int BPF_PROG(
    enter__sys_connect,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen
)
{
    if (!is_event_auditable(RECORD_TYPE_CONNECT))
        return 0;

    struct map_key_process_record map_key;
    init_map_key_process_record(&map_key, RECORD_TYPE_CONNECT);

    struct record_connect map_val;
    map_val.local.addrlen = 0;
    map_val.remote.addrlen = 0;
    long result = bpf_map_update_elem(&process_record_map, &map_key, (void *)&map_val, BPF_ANY);
    if (result != 0)
    {
        LOG_WARN("[enter__sys_connect] Failed to update map. Error = %ld", result);
    }

    return 0;
}

SEC("fexit/__sys_connect")
int BPF_PROG(
    exit__sys_connect,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen,
    int ret
)
{
    if (!is_event_auditable(RECORD_TYPE_CONNECT))
        return 0;

    const int record_type_id = RECORD_TYPE_CONNECT;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

    const pid_t pid = BPF_CORE_READ(current_task, pid);

    struct map_key_process_record map_key;
    init_map_key_process_record(&map_key, record_type_id);

    if (ret != 0 && ret != ERROR_EINPROGRESS)
    {
        bpf_map_delete_elem(&process_record_map, &map_key);
        return 0;
    }

    struct record_connect *map_val = bpf_map_lookup_elem(&process_record_map, &map_key);
    if (!map_val)
    {
        return 0;
    }

    // Get the event id on syscall exit
    const struct elem_common e_common = {
        .record_type_id = record_type_id,
        .event_id = increment_event_id()
    };

    // Get the syscall args on syscall exit
    map_val->fd = fd;
    map_val->ret = ret;
    map_val->pid = pid;
    map_val->e_common = e_common;

    struct elem_sockaddr e_sa;
    e_sa.addrlen = addrlen & (SOCKADDR_MAX_SIZE - 1);
    bpf_probe_read_user(&(e_sa.addr[0]), e_sa.addrlen, sockaddr);
    map_val->remote = e_sa;
    //

    struct bpf_dynptr ptr;
    long dynptr_result = bpf_dynptr_from_mem(map_val, RECORD_SIZE_CONNECT, 0, &ptr);
    if (dynptr_result == 0){
        write_record_to_output_buffer(&ptr, record_type_id);
    } else {
        LOG_WARN("[exit__sys_connect] Failed to create dynptr for record. Error = %ld", dynptr_result);
    }

    bpf_map_delete_elem(&process_record_map, &map_key);

    return 0;
}

struct sockaddr_storage;
SEC("fexit/__sys_connect_file")
int BPF_PROG(
    __sys_connect_file,
    struct file *file,
    struct sockaddr_storage *address,
    int addrlen,
    int file_flags,
    int ret
)
{
    if (!is_event_auditable(RECORD_TYPE_CONNECT))
        return 0;

    struct map_key_process_record map_key;
    init_map_key_process_record(&map_key, RECORD_TYPE_CONNECT);

    if (ret != 0 && ret != ERROR_EINPROGRESS)
    {
        bpf_map_delete_elem(&process_record_map, &map_key);
        return 0;
    }

    struct record_connect *map_val = bpf_map_lookup_elem(&process_record_map, &map_key);
    if (map_val)
    {
        struct socket *sock = bpf_sock_from_file(file);
        if (sock) {
            struct sock_common sk_c = BPF_CORE_READ(sock, sk, __sk_common);
            if (sk_c.skc_family == AF_INET) {
                map_val->local.addrlen = sizeof(struct sockaddr_in);
                struct sockaddr_in *sin = (struct sockaddr_in *)(&map_val->local.addr);
                sin->sin_family = sk_c.skc_family;
                sin->sin_port = sk_c.skc_num;
                sin->sin_addr.s_addr = sk_c.skc_rcv_saddr;
            } else if (sk_c.skc_family == AF_INET6) {
                map_val->local.addrlen = sizeof(struct sockaddr_in6);
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(&map_val->local.addr);
                sin6->sin6_family = sk_c.skc_family;
                sin6->sin6_port = sk_c.skc_num;
                sin6->sin6_addr = sk_c.skc_v6_rcv_saddr;
            }
        }
    } else {
        
    }

    return 0;
}

static u16 local_ntohs(u16 netshort) {
    return (netshort >> 8) | (netshort << 8);
}

SEC("fmod_ret/__arm64_sys_connect")
int BPF_PROG(
    fmod_ret__arm64_sys_connect
)
{
    if (!is_event_auditable(RECORD_TYPE_CONNECT))
        return 0;

    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

    int fd;
    struct sockaddr *addr;
    int addrlen;

    fd = (int)PT_REGS_PARM1(regs);
    addr = (struct sockaddr *)PT_REGS_PARM2(regs);
    addrlen = (int)PT_REGS_PARM3(regs);

    // LOG_WARN("[fmod_ret__arm64_sys_connect] fd=%d", fd);
    // LOG_WARN("[fmod_ret__arm64_sys_connect] addr=%p", addr);
    // LOG_WARN("[fmod_ret__arm64_sys_connect] addrlen=%d", addrlen);

    if (addr != NULL) {

        struct elem_sockaddr e_sa;
        e_sa.addrlen = addrlen & (SOCKADDR_MAX_SIZE - 1);
        bpf_probe_read_user(&(e_sa.addr[0]), e_sa.addrlen, addr);

        struct sockaddr *xaddr = (struct sockaddr *)e_sa.addr;

        unsigned short sa_family = xaddr->sa_family;
        // LOG_WARN("[fmod_ret__arm64_sys_connect] sa_family=%u", sa_family);
        if (sa_family == AF_INET)
        {
            struct sockaddr_in *sin = (struct sockaddr_in *)xaddr;
            u16 port = local_ntohs(sin->sin_port);
            // LOG_WARN("[fmod_ret__arm64_sys_connect] port=%u", port);
            if (port == 5689)
            {
                // return -13; // EACCESS
                // return -1; // EPERM
                // return -22; // EINVAL
                return 0;
            }
        }
    }

    return 0;
}