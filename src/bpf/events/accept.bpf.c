#include "common/vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common/types.h"
#include "bpf/helpers/log.bpf.h"
#include "bpf/helpers/map.bpf.h"
#include "bpf/helpers/event.bpf.h"
#include "bpf/helpers/datatype.bpf.h"
#include "bpf/helpers/copy.bpf.h"
#include "bpf/helpers/output.bpf.h"


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
    __uint(max_entries, MAPS_HASH_MAP_MAX_ENTRIES);
    __type(key, struct map_key_process_record_accept);
    __type(value, struct record_accept);
} process_record_map_accept SEC(".maps");


static int is_accept_event_auditable(void)
{
    struct event_context e_ctx;
    event_init_context(&e_ctx, accept_record_type);
    return event_is_auditable(&e_ctx);
}

static int init_accept_map_key(struct map_key_process_record_accept *map_key, accept_type_fd_t fd_type)
{
    if (!map_key)
        return 0;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);
    map_init_map_key_process_record(&(map_key->map_key), pid, accept_record_type);
    map_key->fd_type = fd_type;
    return 0;
}

static struct record_accept * insert_accept_map_entry_at_syscall_enter(sys_id_t sys_id, accept_type_fd_t fd_type)
{
    struct map_key_process_record_accept map_key;
    init_accept_map_key(&map_key, fd_type);

    struct record_accept map_val;
    datatype_zero_out_record_accept(&map_val, sys_id);
    long result = bpf_map_update_elem(&process_record_map_accept, &map_key, (void *)&map_val, BPF_ANY);
    if (result != 0)
    {
        LOG_WARN("[insert_accept_map_entry_at_syscall_enter] Failed to insert map for fd type: %u. Error = %ld", fd_type, result);
        return NULL;
    }
    return bpf_map_lookup_elem(&process_record_map_accept, &map_key);
}

static int insert_accept_local_map_entry_at_syscall_enter(sys_id_t sys_id, int fd)
{
    struct record_accept * r_accept = insert_accept_map_entry_at_syscall_enter(sys_id, LOCAL);
    if (r_accept)
    {
        datatype_init_fd_record_accept(r_accept, fd);
    }
    return 0;
}

static int insert_accept_remote_map_entry_at_syscall_enter(sys_id_t sys_id)
{
    // Don't know yet since it is returned on sys exit.
    insert_accept_map_entry_at_syscall_enter(sys_id, REMOTE);
    return 0;
}

static int update_accept_map_entry_with_file(accept_type_fd_t fd_type, struct file *file)
{
    if (!file || !is_accept_event_auditable()){
        return 0;
    }

    struct map_key_process_record_accept map_key;
    init_accept_map_key(&map_key, fd_type);

    struct record_accept *map_val = bpf_map_lookup_elem(&process_record_map_accept, &map_key);
    if (!map_val)
    {
        return 0;
    }

    struct socket *sock = bpf_sock_from_file(file);
    if (sock) {
        struct sock_common sk_c = BPF_CORE_READ(sock, sk, __sk_common);
        if (sk_c.skc_family == AF_INET) {
            copy_sockaddr_in_local_from_skc(&(map_val->local), &sk_c);
            copy_sockaddr_in_remote_from_skc(&(map_val->remote), &sk_c);
        } else if (sk_c.skc_family == AF_INET6) {
            copy_sockaddr_in6_local_from_skc(&(map_val->local), &sk_c);
            copy_sockaddr_in6_remote_from_skc(&(map_val->remote), &sk_c);
        }
    }
    return 0;
}

static int update_accept_local_map_entry_with_file(struct file *file)
{
    update_accept_map_entry_with_file(LOCAL, file);
    return 0;
}

static int update_accept_remote_map_entry_with_file(struct file *file)
{
    update_accept_map_entry_with_file(REMOTE, file);
    return 0;
}

static int insert_accept_map_entries_at_syscall_enter(sys_id_t sys_id, int fd)
{
    if (!is_accept_event_auditable())
        return 0;
    insert_accept_local_map_entry_at_syscall_enter(sys_id, fd);
    insert_accept_remote_map_entry_at_syscall_enter(sys_id);
    return 0;
}

static int delete_accept_map_entry(accept_type_fd_t fd_type)
{
    struct map_key_process_record_accept map_key;
    init_accept_map_key(&map_key, fd_type);

    bpf_map_delete_elem(&process_record_map_accept, &map_key);
    return 0;
}

static int delete_accept_local_map_entry(void)
{
    delete_accept_map_entry(LOCAL);
    return 9;
}

static int delete_accept_remote_map_entry(void)
{
    delete_accept_map_entry(REMOTE);
    return 0;
}

static int delete_accept_map_entries(void)
{
    delete_accept_local_map_entry();
    delete_accept_remote_map_entry();
    return 0;
}

static struct record_accept * update_accept_map_entry_on_syscall_exit(event_id_t event_id, accept_type_fd_t fd_type)
{
    if (!is_accept_event_auditable()){
        return NULL;
    }

    struct map_key_process_record_accept map_key;
    init_accept_map_key(&map_key, fd_type);

    struct record_accept *map_val = bpf_map_lookup_elem(&process_record_map_accept, &map_key);
    if (!map_val)
        return NULL;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    map_val->pid = pid;
    map_val->e_ts.event_id = event_id;

    return map_val;
}

static int sys_accept_enter(sys_id_t sys_id, int fd)
{
    insert_accept_map_entries_at_syscall_enter(sys_id, fd);
    return 0;
}

static int sys_accept_exit(int ret_fd)
{
    if (ret_fd == -1)
    {
        delete_accept_map_entries();
        return 0;
    }

    event_id_t event_id = event_increment_id();

    struct record_accept * accept_local = update_accept_map_entry_on_syscall_exit(event_id, LOCAL);
    if (accept_local)
    {
        // fd for accept_local already set on sys_enter
        output_record_accept(accept_local);
    }

    struct record_accept * accept_remote = update_accept_map_entry_on_syscall_exit(event_id, REMOTE);
    if (accept_remote)
    {
        datatype_init_fd_record_accept(accept_remote, ret_fd);
        output_record_accept(accept_remote);
    }

    delete_accept_map_entries();

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
    if (!ret_file){
        delete_accept_map_entries();
        return 0;
    }

    update_accept_local_map_entry_with_file(file);
    update_accept_remote_map_entry_with_file(ret_file);

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
    sys_accept_enter(SYS_ID_ACCEPT4, fd);
    return 0;
}

SEC("fexit/__sys_accept4")
int BPF_PROG(
    exit__sys_accept4,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen,
    int flags,
    int ret_fd
)
{
    sys_accept_exit(ret_fd);
    return 0;
}