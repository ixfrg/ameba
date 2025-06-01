#include "bpf/helpers/event.bpf.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "bpf/helpers/log.bpf.h"
#include "common/control.h"


static event_id_t current_event_id = 0;

static volatile control_lock_t global_control_lock = FREE;
static volatile int global_control_input_is_set = 0;
static struct control_input global_control_input;


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct control_input);
    __uint(max_entries, 1);
} control_input_map SEC(".maps");


int event_init_context(struct event_context *e_ctx, record_type_t r_type)
{
    if (!e_ctx)
        return 0;

    e_ctx->record_type = r_type;

    if (global_control_input_is_set == 1)
    {
        e_ctx->use_global_control_input = 1;
        return 0;
    }

    if (__sync_val_compare_and_swap(&global_control_lock, FREE, TAKEN) == FREE)
    {   
        if (global_control_input_is_set == 0)
        {
            int key = 0;
            struct control_input *val = bpf_map_lookup_elem(&control_input_map, &key);
            if (val)
            {
                __builtin_memcpy(&global_control_input, val, sizeof(struct control_input));

                log_control_input(&global_control_input);

                global_control_input_is_set = 1;
            }
        }
        __sync_val_compare_and_swap(&global_control_lock, TAKEN, FREE);
    }

    return 0;
}

event_id_t event_increment_id(void)
{
    return __sync_fetch_and_add(&current_event_id, 1);
}

static int is_int_in_control_input_id_list(int needle, int *haystack, const int haystack_len)
{
    for (int i = 0; i < haystack_len; i++)
    {
        if (haystack[i] == needle)
            return 1;
    }
    return 0;
}

static int is_task_auditable(struct task_struct *current, struct control_input *runtime_control)
{
    if (!current || !runtime_control)
    {
        return 0;
    }
    
    const uid_t uid = BPF_CORE_READ(current, real_cred, uid).val;
    const pid_t pid = BPF_CORE_READ(current, pid);
    const pid_t ppid = BPF_CORE_READ(current, real_parent, pid);

    int is_uid_in_list = is_int_in_control_input_id_list(
        uid, &(runtime_control->uids[0]), (runtime_control->uids_len & (MAX_LIST_ITEMS - 1))
    );
    int is_pid_in_list = is_int_in_control_input_id_list(
        pid, &(runtime_control->pids[0]), (runtime_control->pids_len & (MAX_LIST_ITEMS - 1))
    );
    int is_ppid_in_list = is_int_in_control_input_id_list(
        ppid, &(runtime_control->ppids[0]), (runtime_control->ppids_len & (MAX_LIST_ITEMS - 1))
    );

    if (runtime_control->uid_mode == IGNORE)
    {
        if (is_uid_in_list)
            return 0;
    }
    if (runtime_control->uid_mode == CAPTURE)
    {
        if (!is_uid_in_list)
            return 0;
    }

    if (runtime_control->pid_mode == IGNORE)
    {
        if (is_pid_in_list)
            return 0;
    }
    if (runtime_control->pid_mode == CAPTURE)
    {
        if (!is_pid_in_list)
            return 0;
    }

    if (runtime_control->ppid_mode == IGNORE)
    {
        if (is_ppid_in_list)
            return 0;
    }
    if (runtime_control->ppid_mode == CAPTURE)
    {
        if (!is_ppid_in_list)
            return 0;
    }

    // We audit if have escaped all kill paths above.
    return 1;
}

int is_record_of_type_network_io(record_type_t t)
{
    switch(t)
    {
        case RECORD_TYPE_SEND_RECV:
            return 1;
        default:
            return 0;
    }
}

int event_is_auditable(struct event_context *e_ctx)
{
    if (!e_ctx)
        return 0;

    if (e_ctx->use_global_control_input == 0)
        return 0;

    struct control_input *ci = &global_control_input;

    trace_mode_t global_mode = ci->global_mode;
    if (global_mode == IGNORE)
        return 0;

    if (is_record_of_type_network_io(e_ctx->record_type))
    {
        if (ci->netio_mode == IGNORE)
            return 0;
    }

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

    return is_task_auditable(current_task, ci);
}