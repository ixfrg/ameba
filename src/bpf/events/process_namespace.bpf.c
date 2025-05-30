#include "common/vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common/types.h"
#include "bpf/helpers/log.bpf.h"
#include "bpf/maps/map.bpf.h"
#include "bpf/helpers/event_context.bpf.h"
#include "bpf/helpers/record_helper.bpf.h"
#include "bpf/ameba.bpf.h"
#include "bpf/helpers/output.bpf.h"


static int send_record_cred(
    struct task_struct *task,
    const sys_id_t sys_id
)
{
    struct event_context e_ctx;
    event_context_init_event_context(&e_ctx, RECORD_TYPE_CRED);
    if (!ameba_is_event_auditable(&e_ctx)){
        return 0;
    }

    struct record_cred r_c;
    recordhelper_init_record_cred(
        &r_c,
        ameba_increment_event_id(),
        BPF_CORE_READ(task, pid),
        sys_id
    );

    r_c.uid = BPF_CORE_READ(task, cred, uid).val;
    r_c.euid = BPF_CORE_READ(task, cred, euid).val;
    r_c.suid = BPF_CORE_READ(task, cred, suid).val;
    r_c.fsuid = BPF_CORE_READ(task, cred, fsuid).val;
    r_c.gid = BPF_CORE_READ(task, cred, gid).val;
    r_c.egid = BPF_CORE_READ(task, cred, egid).val;
    r_c.sgid = BPF_CORE_READ(task, cred, sgid).val;
    r_c.fsgid = BPF_CORE_READ(task, cred, fsgid).val;

    output_record_cred(&r_c);
    return 0;
}


static int send_record_namespace(
    struct task_struct *task,
    const sys_id_t sys_id
)
{
    struct event_context e_ctx;
    event_context_init_event_context(&e_ctx, RECORD_TYPE_NAMESPACE);
    if (!ameba_is_event_auditable(&e_ctx)){
        return 0;
    }

    struct record_namespace r_ns;
    recordhelper_init_record_namespace(
        &r_ns,
        ameba_increment_event_id(),
        BPF_CORE_READ(task, pid),
        sys_id
    );
    r_ns.ns_cgroup = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns).inum;
    r_ns.ns_ipc = BPF_CORE_READ(task, nsproxy, ipc_ns, ns).inum;
    r_ns.ns_mnt = BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
    r_ns.ns_net = BPF_CORE_READ(task, nsproxy, net_ns, ns).inum;
    r_ns.ns_pid_children = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
    r_ns.ns_usr = BPF_CORE_READ(task, cred, user_ns, ns).inum;

    output_record_namespace(&r_ns);
    return 0;
}

static int send_record_new_process(
    struct task_struct *task,
    sys_id_t sys_id
)
{
    struct event_context e_ctx;
    event_context_init_event_context(&e_ctx, RECORD_TYPE_NEW_PROCESS);
    if (!ameba_is_event_auditable(&e_ctx)){
        return 0;
    }

    const struct task_struct *parent_task = (struct task_struct *)bpf_get_current_task_btf();

    struct record_new_process r_np;
    recordhelper_init_record_new_process(
        &r_np,
        ameba_increment_event_id(),
        BPF_CORE_READ(task, pid),
        BPF_CORE_READ(parent_task, pid),
        sys_id
    );

    // bpf_probe_read_kernel(&r_np.comm[0], COMM_MAX_SIZE, &(BPF_CORE_READ(task, comm)[0]));

    output_record_new_process(&r_np);
    return 0;
}

static sys_id_t get_sys_id_from_kernel_clone_args(struct kernel_clone_args *args)
{
    sys_id_t sys_id;

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
    return sys_id;
}

// SEC("fexit/kernel_clone")
// int BPF_PROG(
//     fexit__kernel_clone,
//     struct kernel_clone_args *args,
//     pid_t ret
// )
SEC("fexit/copy_process")
int BPF_PROG(
    fexit__copy_process,
    struct pid *s_pid,
    int trace,
    int node,
    struct kernel_clone_args *args,
    struct task_struct *ret
)
{
    if (ret == NULL)
        return 0;

    sys_id_t sys_id = get_sys_id_from_kernel_clone_args(args);

    send_record_new_process(ret, sys_id);
    send_record_namespace(ret, sys_id);
    send_record_cred(ret, sys_id);

    return 0;
}

SEC("fexit/ksys_unshare")
int BPF_PROG(
    fexit__ksys_unshare,
    unsigned long unshare_flags,
    int ret
)
{
    if (ret == -1)
        return 0;

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    sys_id_t sys_id = SYS_ID_UNSHARE;
    send_record_namespace(current_task, sys_id);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setns")
int trace_setns_exit(struct trace_event_raw_sys_exit *ctx)
{
    long int ret = ctx->ret;

    if (ret == -1)
        return 0;

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    sys_id_t sys_id = SYS_ID_SETNS;
    send_record_namespace(current_task, sys_id);
    return 0;
}