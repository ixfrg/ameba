#include "common/vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include <asm/unistd.h>

#include "common/types.h"
#include "bpf/helpers/log.bpf.h"
#include "bpf/helpers/map.bpf.h"
#include "bpf/helpers/event.bpf.h"
#include "bpf/helpers/event_id.bpf.h"
#include "bpf/helpers/datatype.bpf.h"
#include "bpf/helpers/copy.bpf.h"
#include "bpf/helpers/event.bpf.h"
#include "bpf/helpers/output.bpf.h"


int AMEBA_HOOK(
    "fexit/audit_log_exit",
    fexit__audit_log_exit,
    RECORD_TYPE_AUDIT_LOG_EXIT
)
{
    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

    struct audit_context *audit_context = BPF_CORE_READ(current_task, audit_context);

    if (!audit_context)
        return 0;

    long ret = BPF_CORE_READ(audit_context, return_code);

    int syscall_number = BPF_CORE_READ(audit_context, major);

    switch (syscall_number)
    {
        case __NR_accept:
        case __NR_accept4:
        case __NR_bind:
        case __NR_kill:
        case __NR_setns:
        case __NR_unshare:
        case __NR_clone:
        case __NR_clone3:
            break;
        case __NR_connect:
            if (ret == 0 || ret == ERROR_EINPROGRESS)
            {
                break;
            }
            else
            {
                return 0; //do not log
            }
        case __NR_sendmsg:
        case __NR_sendto:
        case __NR_recvmsg:
        case __NR_recvfrom:
            if (event_is_netio_set_to_ignore())
                return 0; // do not log
            break;
        default:
            return 0; // do not log
    }

    const pid_t pid = BPF_CORE_READ(current_task, pid);
    
    event_id_t event_id = event_id_increment();
    // if (!event_id_get_last_from_task_map(&event_id))
    // {
    //     LOG_WARN("[fexit__audit_log_exit] Failed to get event id");
    // }

    struct record_audit_log_exit r_ale;
    datatype_init_record_audit_log_exit(
        &r_ale,
        pid, event_id, syscall_number
    );

    r_ale.ret = ret;

    copy_las_timestamp_from_current_task(&(r_ale.e_las_ts));

    output_record_audit_log_exit(&r_ale);
    return 0;
}