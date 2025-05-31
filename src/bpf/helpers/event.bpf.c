#include "bpf/helpers/event.bpf.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "bpf/helpers/log.bpf.h"
#include "common/control.h"


static event_id_t current_event_id = 0;

static int is_global_control_input_set = 0;
static struct control_input global_control_input;


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct control_input);
    __uint(max_entries, 1);
} control_input_map SEC(".maps");


static void log_trace_mode(char *key, trace_mode_t t)
{
    char *p;
    switch (t)
    {
        case IGNORE:
            p = "ignore";
            break;
        case CAPTURE:
            p = "capture";
            break;
        default:
            p = "unknown";
            break;
    }
    LOG_WARN("%s: %s", key, p);
}

static void log_control_lock(char *key, control_lock_t t)
{
    char *p;
    switch (t)
    {
        case FREE:
            p = "free";
            break;
        case TAKEN:
            p = "taken";
            break;
        default:
            p = "unknown";
            break;
    }
    LOG_WARN("%s: %s", key, p);
}

static void log_global_control_input(void) {
    struct control_input *ctrl = &global_control_input;
    if (!ctrl) {
        LOG_WARN("global_control_input is NULL");
        return;
    }

    LOG_WARN("=== Control Input Configuration ===");
    log_trace_mode("global_mode", ctrl->global_mode);

    log_trace_mode("uid_mode", ctrl->uid_mode);
    LOG_WARN("uids_len: %d", ctrl->uids_len);
    if (ctrl->uids_len > 0) {
        for (int i = 0; i < ctrl->uids_len && i < MAX_LIST_ITEMS; i++) {
            LOG_WARN("  uid[%d]: %u", i, ctrl->uids[i]);
        }
    }

    log_trace_mode("pid_mode", ctrl->pid_mode);
    LOG_WARN("pids_len: %d", ctrl->pids_len);
    if (ctrl->pids_len > 0) {
        for (int i = 0; i < ctrl->pids_len && i < MAX_LIST_ITEMS; i++) {
            LOG_WARN("  pid[%d]: %d", i, ctrl->pids[i]);
        }
    }

    log_trace_mode("ppid_mode", ctrl->ppid_mode);
    LOG_WARN("ppids_len: %d", ctrl->ppids_len);
    if (ctrl->ppids_len > 0) {
        for (int i = 0; i < ctrl->ppids_len && i < MAX_LIST_ITEMS; i++) {
            LOG_WARN("  ppid[%d]: %d", i, ctrl->ppids[i]);
        }
    }

    log_trace_mode("netio_mode", ctrl->netio_mode);
    
    log_control_lock("lock", ctrl->lock);
    
    LOG_WARN("=== End Control Input ===");
}

static int set_global_control_input_from_map(void){
    int key;
    key = 0;

    struct control_input *val;
    val = bpf_map_lookup_elem(&control_input_map, &key);
    if (val)
    {
        if (
            is_global_control_input_set == 0
            && __sync_val_compare_and_swap(&(val->lock), FREE, TAKEN) == FREE
        )
        {
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

            global_control_input.global_mode = val->global_mode;

            global_control_input.lock = val->lock;

            log_global_control_input();

            is_global_control_input_set = 1;

            __sync_val_compare_and_swap(&(val->lock), TAKEN, FREE);
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