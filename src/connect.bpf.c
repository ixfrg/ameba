#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "record.h"


extern long write_record_to_output_buffer(struct bpf_dynptr *ptr, int record_type);
extern unsigned long increment_event_id(void);


struct map_key_process_record
{
    pid_t pid;
    int record_type_id;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // TODO
    __type(key, struct map_key_process_record);
    __type(value, struct record_connect);
} process_record_map SEC(".maps");



static void init_connect_map_key(struct map_key_process_record *map_key, const int record_type_id)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    pid_t pid = BPF_CORE_READ(current_task, pid);
    map_key->pid = pid;
    map_key->record_type_id = record_type_id;
}

//


SEC("fentry/__sys_connect")
int BPF_PROG(
    enter__sys_connect,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen
)
{
    struct map_key_process_record map_key;
    init_connect_map_key(&map_key, RECORD_TYPE_CONNECT);

    struct record_connect map_val;

    bpf_map_update_elem(&process_record_map, &map_key, (void *)&map_val, BPF_ANY);

    // bpf_trace_printk("%s\\n", sizeof("%s\\n"), "update enter__sys_connect");

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
    const int record_type_id = RECORD_TYPE_CONNECT;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

    const pid_t pid = BPF_CORE_READ(current_task, pid);

    struct map_key_process_record map_key;
    init_connect_map_key(&map_key, record_type_id);

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
    const struct record_common r_common = {
        .record_type_id = record_type_id,
        .event_id = increment_event_id()
    };

    // Get the syscall args on syscall exit
    map_val->fd = fd;
    map_val->ret = ret;
    map_val->pid = pid;
    map_val->r_common = r_common;

    struct record_sockaddr r_sa;
    r_sa.addrlen = addrlen & (SOCKADDR_MAX_SIZE - 1);
    bpf_probe_read_user(&(r_sa.addr[0]), r_sa.addrlen, sockaddr);
    map_val->remote = r_sa;
    //

    struct bpf_dynptr ptr;
    if (bpf_dynptr_from_mem(map_val, RECORD_SIZE_CONNECT, 0, &ptr) == 0){
        write_record_to_output_buffer(&ptr, RECORD_TYPE_CONNECT);
    } else {
        bpf_trace_printk("%s\\n", sizeof("%s\\n"), "some error");
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
    struct map_key_process_record map_key;
    init_connect_map_key(&map_key, RECORD_TYPE_CONNECT);

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
                struct sockaddr_in *sin = (struct sockaddr_in *)(&map_val->local);
                sin->sin_family = sk_c.skc_family;
                sin->sin_port = sk_c.skc_num;
                sin->sin_addr.s_addr = sk_c.skc_rcv_saddr;
            } else if (sk_c.skc_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(&map_val->local);
                sin6->sin6_family = sk_c.skc_family;
                sin6->sin6_port = sk_c.skc_num;
                sin6->sin6_addr = sk_c.skc_v6_rcv_saddr;
            }
            // bpf_trace_printk("%s\\n", sizeof("%s\\n"), "in-place-update __sys_connect_file");
        }
    } else {
        // log_warn("No map entry found for value... TODO more helpful info", 0);
    }

    return 0;
}