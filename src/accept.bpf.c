#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "record.h"


struct map_key_process_record_accept
{
    struct map_key_process_record map_key;
    unsigned char fd_type;
};


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
    long result = bpf_map_update_elem(&process_record_map_accept, &map_key, (void *)&map_val, BPF_ANY);
    if (result != 0)
    {
        LOG_WARN("[enter__sys_accept4] Failed to update map for fd type: %u. Error = %ld", fd_type, result);
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
    return 0;
}
