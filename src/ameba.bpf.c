#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "record.h"

char _license[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} ameba_ringbuf SEC(".maps");

unsigned long current_event_id = 0;

unsigned long increment_event_id(void)
{
    return __sync_fetch_and_add(&current_event_id, 1);
}

long write_record_to_output_buffer(struct bpf_dynptr *ptr, int record_type){
    if (ptr != NULL){
        void *data = NULL;
        u32 size = 0;
        switch(record_type)
        {
            case RECORD_TYPE_CONNECT:
                size = RECORD_SIZE_CONNECT;
                data = bpf_dynptr_data(ptr, 0, RECORD_SIZE_CONNECT);
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

