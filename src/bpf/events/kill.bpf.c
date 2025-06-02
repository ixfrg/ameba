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
#include "bpf/helpers/output.bpf.h"


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


struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAPS_HASH_MAP_MAX_ENTRIES); // TODO
    __type(key, struct map_key_process_record);
    __type(value, struct record_kill);
} process_record_map_kill SEC(".maps");


static int init_kill_map_key(struct map_key_process_record *map_key)
{
    if (!map_key)
        return 0;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    map_init_map_key_process_record(map_key, pid, kill_record_type);
    return 0;
}

static int insert_kill_map_entry_at_syscall_enter(pid_t target_pid, int sig)
{

    struct map_key_process_record map_key;
    init_kill_map_key(&map_key);

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t acting_pid = BPF_CORE_READ(current_task, pid);

    struct record_kill map_val;
    datatype_init_record_kill(
        &map_val, 
        acting_pid, 
        target_pid,
        sig
    );
    long result = bpf_map_update_elem(&process_record_map_kill, &map_key, (void *)&map_val, BPF_ANY);
    if (result != 0)
    {
        LOG_WARN("[insert_kill_map_entry_at_syscall_enter] Failed to do map insert. Error = %ld", result);
    }

    return 0;
}

static int delete_kill_map_entry(void)
{
    struct map_key_process_record map_key;
    init_kill_map_key(&map_key);

    bpf_map_delete_elem(&process_record_map_kill, &map_key);

    return 0;
}

static int update_kill_map_entry_on_syscall_exit(int ret)
{

    struct map_key_process_record map_key;
    init_kill_map_key(&map_key);

    struct record_kill *map_val = bpf_map_lookup_elem(&process_record_map_kill, &map_key);
    if (!map_val)
        return 0;

    map_val->e_ts.event_id = event_increment_id();
    map_val->ret = ret;

    if (ret == -1)
    {
        // check for UBSI
        switch (map_val->target_pid)
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
    }

    return 0;
}

static int send_kill_map_entry_on_syscall_exit(void)
{

    struct map_key_process_record map_key;
    init_kill_map_key(&map_key);

    struct record_kill *map_val = bpf_map_lookup_elem(&process_record_map_kill, &map_key);
    if (!map_val)
        return 0;

    output_record_kill(map_val);

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