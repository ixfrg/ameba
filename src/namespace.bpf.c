#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "record.h"

extern int is_event_auditable(int record_type);
extern long write_record_to_output_buffer(struct bpf_dynptr *ptr, int record_type);
extern long write_record_namespace_to_output_buffer(struct record_namespace *ptr);
extern long write_record_new_process_to_output_buffer(struct record_new_process *ptr);
extern unsigned long increment_event_id(void);
extern long init_map_key_process_record(struct map_key_process_record *map_key, const int record_type_id);


static int ns_update(
    const int sys_id,
    const int ret
)
{
    struct task_struct *current_task;

    current_task = (struct task_struct *)bpf_get_current_task_btf();

    int record_type_id = RECORD_TYPE_NAMESPACE;

    struct record_namespace r_ns;
    r_ns.e_common.event_id = increment_event_id();
    r_ns.e_common.record_type_id = record_type_id;
    r_ns.pid = BPF_CORE_READ(current_task, pid);
    r_ns.sys_id = sys_id;
    r_ns.ret = ret;
    r_ns.ns_cgroup = BPF_CORE_READ(current_task, nsproxy, cgroup_ns, ns).inum;
    r_ns.ns_ipc = BPF_CORE_READ(current_task, nsproxy, ipc_ns, ns).inum;
    r_ns.ns_mnt = BPF_CORE_READ(current_task, nsproxy, mnt_ns, ns).inum;
    r_ns.ns_net = BPF_CORE_READ(current_task, nsproxy, net_ns, ns).inum;
    r_ns.ns_pid_children = BPF_CORE_READ(current_task, nsproxy, pid_ns_for_children, ns).inum;
    r_ns.ns_usr = BPF_CORE_READ(current_task, cred, user_ns, ns).inum;

    write_record_namespace_to_output_buffer(&r_ns);

    return 0;
}


SEC("fexit/kernel_clone")
int BPF_PROG(
    exit__kernel_clone,
    struct kernel_clone_args *args,
    pid_t ret
)
{
    int record_type = RECORD_TYPE_NEW_PROCESS;

    if (!is_event_auditable(record_type))
        return 0;

    if (ret == -1)
    {
        return 0;
    }

    int sys_id;

    sys_id = SYS_ID_CLONE; // by default

    if (BPF_CORE_READ(args, exit_signal) == SIGCHLD)
    {
        if (BPF_CORE_READ(args, flags) == (CLONE_VFORK | CLONE_VM))
        {
            sys_id = SYS_ID_VFORK;
        }
        else if (BPF_CORE_READ(args, flags) == 0)
        {
            sys_id = SYS_ID_FORK;
        }
    }

    unsigned long event_id = increment_event_id();

    const struct task_struct *parent_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t parent_pid = BPF_CORE_READ(parent_task, pid);

    struct record_new_process r_np;
    r_np.e_common.event_id = event_id;
    r_np.e_common.record_type_id = record_type;
    r_np.pid = ret; // NOT FROM ROOT PID NAMESPACE!!!
    r_np.ppid = parent_pid;
    r_np.sys_id = sys_id;
    bpf_get_current_comm(&r_np.comm[0], COMM_MAX_SIZE);

    write_record_new_process_to_output_buffer(&r_np);

    return 0;

    /*
    
        NOTE!!! BELOW!!!
    
    */

    // The following is for namespace

    // if (!is_event_auditable(-1))
    //     return 0;

    // if (ret == -1)
    // {
    //     return 0;
    // }

    // int sys_id;

    // sys_id = SYS_ID_CLONE; // by default

    // if (BPF_CORE_READ(args, exit_signal) == SIGCHLD)
    // {
    //     if (BPF_CORE_READ(args, flags) == (CLONE_VFORK | CLONE_VM))
    //     {
    //         sys_id = SYS_ID_VFORK;
    //     }
    //     else if (BPF_CORE_READ(args, flags) == 0)
    //     {
    //         sys_id = SYS_ID_FORK;
    //     }
    // }

    // return ns_update(sys_id, ret);
}

SEC("fexit/ksys_unshare")
int BPF_PROG(
    exit__ksys_unshare,
    unsigned long unshare_flags,
    int ret
)
{
    if (!is_event_auditable(RECORD_TYPE_NAMESPACE))
        return 0;

    if (ret == -1)
    {
        return 0;
    }

    int sys_id;

    sys_id = SYS_ID_UNSHARE;

    return ns_update(sys_id, ret);
}

SEC("tracepoint/syscalls/sys_exit_setns")
int trace_setns_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_event_auditable(RECORD_TYPE_NAMESPACE))
        return 0;

    long int ret = ctx->ret;

    if (ret == -1)
    {
        return 0;
    }

    int sys_id;

    sys_id = SYS_ID_SETNS;

    return ns_update(sys_id, ret);
}