#include "common/vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common/types.h"
#include "bpf/helpers/log.bpf.h"
#include "bpf/helpers/map.bpf.h"
#include "bpf/helpers/event.bpf.h"
#include "bpf/helpers/event_id.bpf.h"
#include "bpf/helpers/datatype.bpf.h"
#include "bpf/helpers/copy.bpf.h"
#include "bpf/helpers/output.bpf.h"
#include "bpf/events/kill/storage.bpf.h"


// UBSI kill values
#define UENTRY		0xffffff9c // -100
#define UENTRY_ID	0xffffff9a // -102
#define UEXIT		0xffffff9b // -101
#define MREAD1		0xffffff38 // -200
#define MREAD2		0xffffff37 // -201
#define MWRITE1 	0xfffffed4 // -300
#define MWRITE2 	0xfffffed3 // -301
#define UDEP		0xfffffe70 // -400


// local globals
static const record_type_t kill_record_type = RECORD_TYPE_KILL;


static int insert_kill_map_entry_at_syscall_enter(pid_t target_pid, int sig)
{
    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t acting_pid = BPF_CORE_READ(current_task, pid);

    struct record_kill map_val;
    datatype_init_record_kill(
        &map_val, 
        acting_pid, 
        target_pid,
        sig
    );

    if (!kill_storage_insert(&map_val))
    {
        LOG_WARN("[insert_kill_map_entry_at_syscall_enter] Failed to do map insert");
    }

    return 0;
}

static int delete_kill_map_entry(void)
{
    kill_storage_delete();
    return 0;
}

static int update_kill_map_entry_on_syscall_exit(int ret)
{
    kill_storage_set_props_on_sys_exit(ret, event_id_increment());

    if (ret == -1)
    {
        pid_t target_pid = kill_storage_get_target_pid();
        // check for UBSI
        switch (target_pid)
        {
            case UENTRY:
            case UENTRY_ID:
            case UEXIT:
            case MREAD1:
            case MREAD2:
            case MWRITE1:
            case MWRITE2:
            case UDEP:
                // Do log
                break;
            default:
                delete_kill_map_entry();
                break; // DO NOT log
        }
    } else 
    {
        // Do log
    }

    return 0;
}

static int send_kill_map_entry_on_syscall_exit(void)
{
    kill_storage_output();
    return 0;
}

int AMEBA_HOOK_TP(
    "tracepoint/syscalls/sys_enter_kill",
    trace_kill_enter,
    kill_record_type,
    struct trace_event_raw_sys_enter *, ctx
)
{
    pid_t target_pid = BPF_CORE_READ(ctx, args[0]);
    int sig = BPF_CORE_READ(ctx, args[1]);

    insert_kill_map_entry_at_syscall_enter(target_pid, sig);

    return 0;
}

int AMEBA_HOOK_TP(
    "tracepoint/syscalls/sys_exit_kill",
    trace_kill_exit,
    kill_record_type,
    struct trace_event_raw_sys_exit *, ctx
)
{
    long int ret = ctx->ret;

    update_kill_map_entry_on_syscall_exit(ret);
    send_kill_map_entry_on_syscall_exit();
    delete_kill_map_entry();
    
    return 0;
}