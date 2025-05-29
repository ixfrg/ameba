#include "common/vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "bpf/ameba.bpf.h"
#include "common/types.h"
#include "bpf/helpers/log.bpf.h"


// special
char _license[] SEC("license") = "GPL";


// maps
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} ameba_ringbuf SEC(".maps");


// local globals
static event_id_t current_event_id = 0;


// extern functions
event_id_t ameba_increment_event_id(void)
{
    return __sync_fetch_and_add(&current_event_id, 1);
}

int ameba_is_event_auditable(struct event_context *e_ctx)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    uid_t uid = BPF_CORE_READ(current_task, real_cred, uid).val;
    // "uid=1001(audited_user) gid=1001(audited_user) groups=1001(audited_user),100(users)"
    // if (record_type == RECORD_TYPE_NAMESPACE)
    // {
    //     return uid == 0;
    // }
    return uid == 1001;
}

long ameba_write_record_cred_to_output_buffer(struct record_cred *ptr)
{
    if (ptr == NULL){
        return 0;
    }
    return bpf_ringbuf_output(&ameba_ringbuf, ptr, RECORD_SIZE_CRED, 0);
}

long ameba_write_record_namespace_to_output_buffer(struct record_namespace *ptr)
{
    if (ptr == NULL){
        return 0;
    }
    return bpf_ringbuf_output(&ameba_ringbuf, ptr, RECORD_SIZE_NAMESPACE, 0);
}

long ameba_write_record_new_process_to_output_buffer(struct record_new_process *ptr)
{
    if (ptr == NULL){
        return 0;
    }
    return bpf_ringbuf_output(&ameba_ringbuf, ptr, RECORD_SIZE_NEW_PROCESS, 0);
}

long ameba_write_record_accept_to_output_buffer(struct record_accept *ptr)
{
    if (ptr == NULL){
        return 0;
    }
    return bpf_ringbuf_output(&ameba_ringbuf, ptr, RECORD_SIZE_ACCEPT, 0);
}

long ameba_write_record_send_to_output_buffer(struct record_send *ptr)
{
    if (ptr == NULL){
        return 0;
    }
    return bpf_ringbuf_output(&ameba_ringbuf, ptr, RECORD_SIZE_SEND, 0);
}

long ameba_write_record_to_output_buffer(struct bpf_dynptr *ptr, record_type_t record_type){
    if (ptr != NULL){
        void *data = NULL;
        size_t size = 0;
        switch(record_type)
        {
            case RECORD_TYPE_CONNECT:
                size = RECORD_SIZE_CONNECT;
                data = bpf_dynptr_data(ptr, 0, RECORD_SIZE_CONNECT);
                break;
            case RECORD_TYPE_ACCEPT:
                size = RECORD_SIZE_ACCEPT;
                data = bpf_dynptr_data(ptr, 0, RECORD_SIZE_ACCEPT);
                break;
            case RECORD_TYPE_NAMESPACE:
                size = RECORD_SIZE_NAMESPACE;
                data = bpf_dynptr_data(ptr, 0, RECORD_SIZE_NAMESPACE);
                break;
            case RECORD_TYPE_NEW_PROCESS:
                size = RECORD_SIZE_NEW_PROCESS;
                data = bpf_dynptr_data(ptr, 0, RECORD_SIZE_NEW_PROCESS);
                break;
            default: break;
        }
        if (data != NULL){
            return bpf_ringbuf_output(&ameba_ringbuf, data, size, 0);
        } else {
            LOG_WARN("Unknown record to output ring buffer. Type = %d", record_type);
            return 0;
        }
    } else {
        return 0;
    }
}

