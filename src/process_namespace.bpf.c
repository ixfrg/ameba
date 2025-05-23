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


static int send_record_namespace(
    struct task_struct *task,
    const int sys_id
)
{
    int record_type_id = RECORD_TYPE_NAMESPACE;

    struct record_namespace r_ns;
    r_ns.e_common.event_id = increment_event_id();
    r_ns.e_common.record_type_id = record_type_id;
    r_ns.pid = BPF_CORE_READ(task, pid);
    r_ns.sys_id = sys_id;
    r_ns.ns_cgroup = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns).inum;
    r_ns.ns_ipc = BPF_CORE_READ(task, nsproxy, ipc_ns, ns).inum;
    r_ns.ns_mnt = BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
    r_ns.ns_net = BPF_CORE_READ(task, nsproxy, net_ns, ns).inum;
    r_ns.ns_pid_children = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
    r_ns.ns_usr = BPF_CORE_READ(task, cred, user_ns, ns).inum;

    write_record_namespace_to_output_buffer(&r_ns);

    return 0;
}

static int send_record_new_process(
    struct task_struct *task,
    int sys_id
)
{
    int record_type = RECORD_TYPE_NEW_PROCESS;

    unsigned long event_id = increment_event_id();

    const struct task_struct *parent_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t parent_pid = BPF_CORE_READ(parent_task, pid);

    struct record_new_process r_np;
    r_np.e_common.event_id = event_id;
    r_np.e_common.record_type_id = record_type;
    r_np.pid = BPF_CORE_READ(task, pid);
    r_np.ppid = parent_pid;
    r_np.sys_id = sys_id;

    write_record_new_process_to_output_buffer(&r_np);
    return 0;
}


// SEC("fexit/kernel_clone")
// int BPF_PROG(
//     exit__kernel_clone,
//     struct kernel_clone_args *args,
//     pid_t ret
// )
SEC("fexit/copy_process")
int BPF_PROG(
    exit__copy_process,
    struct pid *s_pid,
    int trace,
    int node,
    struct kernel_clone_args *args,
    struct task_struct *ret
)
{
    if (ret == NULL)
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

    if (is_event_auditable(RECORD_TYPE_NEW_PROCESS))
    {
        send_record_new_process(ret, sys_id);
    }

    if (is_event_auditable(RECORD_TYPE_NAMESPACE))
    {
        send_record_namespace(ret, sys_id);
    }

    return 0;
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

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

    int sys_id;

    sys_id = SYS_ID_UNSHARE;

    return send_record_namespace(current_task, sys_id);
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

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

    int sys_id;

    sys_id = SYS_ID_SETNS;

    return send_record_namespace(current_task, sys_id);
}