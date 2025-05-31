#include "bpf/helpers/event.bpf.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "bpf/helpers/log.bpf.h"
#include "common/control.h"


static event_id_t current_event_id = 0;


static struct control_input global_control_input = {
    .global_mode = NOT_SET
};


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct control_input);
    __uint(max_entries, 1);
} control_input_map SEC(".maps");


static void log_global_control_input() {
    struct control_input *ctrl = &global_control_input;
    if (!ctrl) {
        LOG_WARN("control_input is NULL");
        return;
    }

    LOG_WARN("=== Control Input Configuration ===");
    LOG_WARN("global_mode: %d", ctrl->global_mode);

    LOG_WARN("uid_mode: %d, uids_len: %d", ctrl->uid_mode, ctrl->uids_len);
    if (ctrl->uids_len > 0) {
        for (int i = 0; i < ctrl->uids_len && i < MAX_LIST_ITEMS; i++) {
            LOG_WARN("  uid[%d]: %u", i, ctrl->uids[i]);
        }
    }

    LOG_WARN("pid_mode: %d, pids_len: %d", ctrl->pid_mode, ctrl->pids_len);
    if (ctrl->pids_len > 0) {
        for (int i = 0; i < ctrl->pids_len && i < MAX_LIST_ITEMS; i++) {
            LOG_WARN("  pid[%d]: %d", i, ctrl->pids[i]);
        }
    }

    LOG_WARN("ppid_mode: %d, ppids_len: %d", ctrl->ppid_mode, ctrl->ppids_len);
    if (ctrl->ppids_len > 0) {
        for (int i = 0; i < ctrl->ppids_len && i < MAX_LIST_ITEMS; i++) {
            LOG_WARN("  ppid[%d]: %d", i, ctrl->ppids[i]);
        }
    }

    LOG_WARN("netio_mode: %d", ctrl->netio_mode);
    
#ifdef USE_BPF_SPIN_LOCK
    LOG_WARN("spin_lock configured");
#endif
    
    LOG_WARN("=== End Control Input ===");
}

static int set_global_control_input_from_map(){
    int key;
    key = 0;

    if (
        // Only do if first event i.e. event id is 0.
        current_event_id == 0
        // Only do if not already set.
        // Set to ignore so that events are ignored until properly updated.
        && __sync_val_compare_and_swap(&(global_control_input.global_mode), NOT_SET, IGNORE) != IGNORE
        // && __sync_lock_test_and_set(&global_control_input.global_mode, IGNORE) == NOT_SET
    )
    {
        struct control_input *val;
        val = bpf_map_lookup_elem(&control_input_map, &key);
        if (val)
        {
            #ifdef USE_BPF_SPIN_LOCK
            bpf_spin_lock(&val->lock);
            #endif

            global_control_input.uid_mode = val->uid_mode;
            global_control_input.uids_len = val->uids_len;
            for (int i = 0; i < MAX_LIST_ITEMS; i++){
                global_control_input.uids[i] = val->uids[i];
            }
            
            global_control_input.pid_mode = val->pid_mode;
            global_control_input.pids_len = val->pids_len;
            for (int i = 0; i < MAX_LIST_ITEMS; i++){
                global_control_input.pids[i] = val->pids[i];
            }

            global_control_input.ppid_mode = val->ppid_mode;
            global_control_input.ppids_len = val->ppids_len;
            for (int i = 0; i < MAX_LIST_ITEMS; i++){
                global_control_input.ppids[i] = val->ppids[i];
            }

            global_control_input.netio_mode = val->netio_mode;

            log_global_control_input();

            // Last.. after updating the rest of the struct.
            __sync_lock_test_and_set(&global_control_input.global_mode, val->global_mode);

            #ifdef USE_BPF_SPIN_LOCK
            bpf_spin_unlock(&val->lock);
            #endif
        }
    }
    return 0;
}

int event_init_context(struct event_context *e_ctx, record_type_t r_type)
{
    if (!e_ctx)
        return 0;
    e_ctx->record_type = r_type;
    return 0;
}

event_id_t event_increment_id(void)
{
    return __sync_fetch_and_add(&current_event_id, 1);
}

int event_is_auditable(struct event_context *e_ctx)
{
    set_global_control_input_from_map();

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    // const pid_t pid = BPF_CORE_READ(current_task, pid);
    uid_t uid = BPF_CORE_READ(current_task, real_cred, uid).val;

    // "uid=1001(audited_user) gid=1001(audited_user) groups=1001(audited_user),100(users)"
    // if (record_type == RECORD_TYPE_NAMESPACE)
    // {
    //     return uid == 0;
    // }
    return uid == 1001;
}