#include "bpf/helpers/log.bpf.h"



int log_trace_mode(char *key, trace_mode_t t)
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
    return 0;
}

int log_control_lock(char *key, control_lock_t t)
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
    return 0;
}

int log_control_input(struct control_input *ctrl) {
    if (!ctrl) {
        LOG_WARN("control_input is NULL");
        return 0;
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
    return 0;
}