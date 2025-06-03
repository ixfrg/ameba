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
#include "bpf/helpers/event.bpf.h"
#include "bpf/helpers/output.bpf.h"


typedef enum
{
    SYS_ACCEPT = 202,
    SYS_ACCEPT4 = 204,
    SYS_BIND = 200,
    SYS_CONNECT = 203,
    SYS_KILL = 129,
    SYS_SENDMSG = 211,
    SYS_SENDTO = 206,
    SYS_RECVMSG = 212,
    SYS_RECVFROM = 207,
    SYS_SETNS = 268,
    SYS_UNSHARE = 97,
    SYS_CLONE = 220,
    SYS_CLONE3 = 435
} syscall_number_t;


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

    int syscall_number = BPF_CORE_READ(audit_context, major);

    switch (syscall_number)
    {
        case SYS_ACCEPT:
        case SYS_ACCEPT4:
        case SYS_BIND:
        case SYS_CONNECT:
        case SYS_KILL:
        case SYS_SETNS:
        case SYS_UNSHARE:
        case SYS_CLONE:
        case SYS_CLONE3:
            break;
        case SYS_SENDMSG:
        case SYS_SENDTO:
        case SYS_RECVMSG:
        case SYS_RECVFROM:
            if (event_is_netio_set_to_ignore())
                return 0; // do not log
            break;
        default:
            return 0; // do not log
    }

    const pid_t pid = BPF_CORE_READ(current_task, pid);
    
    struct record_audit_log_exit r_ale;
    datatype_init_record_audit_log_exit(
        &r_ale,
        pid, event_increment_id(), syscall_number
    );

    copy_las_timestamp_from_current_task(&(r_ale.e_las_ts));

    output_record_audit_log_exit(&r_ale);
    return 0;
}