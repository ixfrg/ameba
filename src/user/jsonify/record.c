#include "user/jsonify/record.h"
#include "user/error.h"


static int jsonify_record_connect(struct json_buffer *s, struct record_connect *data, int write_interpreted)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_connect");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_fd(s, "fd", data->fd);
    total += jsonify_types_write_return(s, "ret", data->ret);
    total += jsonify_types_write_inode(s, "ns_net", data->ns_net);
    total += jsonify_core_write_short(s, "sock_type", data->sock_type);
    total += jsonify_types_write_elem_sockaddr(s, "local", &(data->local), write_interpreted);
    total += jsonify_types_write_elem_sockaddr(s, "remote", &(data->remote), write_interpreted);

    return total;
}

static int jsonify_record_accept(struct json_buffer *s, struct record_accept *data, int write_interpreted)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_accept");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_sys_id(s, data->sys_id, write_interpreted);
    total += jsonify_types_write_fd(s, "fd", data->fd);
    total += jsonify_types_write_return(s, "ret", data->ret);
    total += jsonify_types_write_inode(s, "ns_net", data->ns_net);
    total += jsonify_core_write_short(s, "sock_type", data->sock_type);
    total += jsonify_types_write_elem_sockaddr(s, "local", &(data->local), write_interpreted);
    total += jsonify_types_write_elem_sockaddr(s, "remote", &(data->remote), write_interpreted);

    return total;
}

static int jsonify_record_namespace(struct json_buffer *s, struct record_namespace *data, int write_interpreted)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_namespace");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_sys_id(s, data->sys_id, write_interpreted);
    total += jsonify_types_write_inode(s, "ns_ipc", data->ns_ipc);
    total += jsonify_types_write_inode(s, "ns_mnt", data->ns_mnt);
    total += jsonify_types_write_inode(s, "ns_pid_children", data->ns_pid_children);
    total += jsonify_types_write_inode(s, "ns_pid", data->ns_pid);
    total += jsonify_types_write_inode(s, "ns_net", data->ns_net);
    total += jsonify_types_write_inode(s, "ns_cgroup", data->ns_cgroup);
    total += jsonify_types_write_inode(s, "ns_usr", data->ns_usr);

    return total;
}

static int jsonify_record_new_process(struct json_buffer *s, struct record_new_process *data, int write_interpreted)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_new_process");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_pid(s, "ppid", data->ppid);
    total += jsonify_types_write_sys_id(s, data->sys_id, write_interpreted);
    total += jsonify_core_write_str(s, "comm", &data->comm[0]);
    // total += jsonify_types_write_elem_las_timestamp(s, &data->e_las_ts);

    return total;
}

static int jsonify_record_cred(struct json_buffer *s, struct record_cred *data, int write_interpreted)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_cred");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_sys_id(s, data->sys_id, write_interpreted);
    total += jsonify_types_write_uid(s, "uid", data->uid);
    total += jsonify_types_write_uid(s, "euid", data->euid);
    total += jsonify_types_write_uid(s, "suid", data->suid);
    total += jsonify_types_write_uid(s, "fsuid", data->fsuid);
    total += jsonify_types_write_gid(s, "gid", data->gid);
    total += jsonify_types_write_gid(s, "egid", data->egid);
    total += jsonify_types_write_gid(s, "sgid", data->sgid);
    total += jsonify_types_write_gid(s, "fsgid", data->fsgid);

    return total;
}

static int jsonify_record_send_recv(struct json_buffer *s, struct record_send_recv *data, int write_interpreted)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_send_recv");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_sys_id(s, data->sys_id, write_interpreted);
    total += jsonify_types_write_fd(s, "fd", data->fd);
    total += jsonify_types_write_ssize(s, "ret", data->ret);
    total += jsonify_types_write_inode(s, "ns_net", data->ns_net);
    total += jsonify_core_write_short(s, "sock_type", data->sock_type);
    total += jsonify_types_write_elem_sockaddr(s, "local", &(data->local), write_interpreted);
    total += jsonify_types_write_elem_sockaddr(s, "remote", &(data->remote), write_interpreted);

    return total;
}

static int jsonify_record_bind(struct json_buffer *s, struct record_bind *data, int write_interpreted)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_bind");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_fd(s, "fd", data->fd);
    total += jsonify_types_write_inode(s, "ns_net", data->ns_net);
    total += jsonify_core_write_short(s, "sock_type", data->sock_type);
    total += jsonify_types_write_elem_sockaddr(s, "local", &(data->local),  write_interpreted);
    // total += jsonify_types_write_elem_sockaddr(s, "remote", &(data->remote));

    return total;
}

static int jsonify_record_kill(struct json_buffer *s, struct record_kill *data, int write_interpreted)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_kill");
    total += jsonify_types_write_pid(s, "acting_pid", data->acting_pid);
    total += jsonify_core_write_int(s, "sig", data->sig);
    total += jsonify_types_write_pid(s, "target_pid", data->target_pid);
    total += jsonify_types_write_return(s, "ret", data->ret);

    return total;
}

static int jsonify_record_audit_log_exit(struct json_buffer *s, struct record_audit_log_exit *data, int write_interpreted)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_audit_log_exit");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_core_write_int(s, "syscall_number", data->syscall_number);
    total += jsonify_core_write_long(s, "exit", data->ret);
    total += jsonify_types_write_elem_las_timestamp(s, &data->e_las_ts);

    return total;
}

int jsonify_record(struct json_buffer *s, struct elem_common *e_common, int data_len, int write_interpreted)
{
    switch (e_common->record_type)
    {
        case RECORD_TYPE_CONNECT:
            if (data_len != sizeof(struct record_connect))
                return ERR_RECORD_SIZE_MISMATCH;
            return jsonify_record_connect(s, (struct record_connect *)e_common, write_interpreted);
        case RECORD_TYPE_ACCEPT:
            if (data_len != sizeof(struct record_accept))
                return ERR_RECORD_SIZE_MISMATCH;
            return jsonify_record_accept(s, (struct record_accept *)e_common, write_interpreted);
        case RECORD_TYPE_NAMESPACE:
            if (data_len != sizeof(struct record_namespace))
                return ERR_RECORD_SIZE_MISMATCH;
            return jsonify_record_namespace(s, (struct record_namespace *)e_common, write_interpreted);
        case RECORD_TYPE_NEW_PROCESS:
            if (data_len != sizeof(struct record_new_process))
                return ERR_RECORD_SIZE_MISMATCH;
            return jsonify_record_new_process(s, (struct record_new_process *)e_common, write_interpreted);
        case RECORD_TYPE_CRED:
            if (data_len != sizeof(struct record_cred))
                return ERR_RECORD_SIZE_MISMATCH;
            return jsonify_record_cred(s, (struct record_cred *)e_common, write_interpreted);
        case RECORD_TYPE_SEND_RECV:
            if (data_len != sizeof(struct record_send_recv))
                return ERR_RECORD_SIZE_MISMATCH;
            return jsonify_record_send_recv(s, (struct record_send_recv *)e_common, write_interpreted);
        case RECORD_TYPE_BIND:
            if (data_len != sizeof(struct record_bind))
                return ERR_RECORD_SIZE_MISMATCH;
            return jsonify_record_bind(s, (struct record_bind *)e_common, write_interpreted);
        case RECORD_TYPE_KILL:
            if (data_len != sizeof(struct record_kill))
                return ERR_RECORD_SIZE_MISMATCH;
            return jsonify_record_kill(s, (struct record_kill *)e_common, write_interpreted);
        case RECORD_TYPE_AUDIT_LOG_EXIT:
            if (data_len != sizeof(struct record_audit_log_exit))
                return ERR_RECORD_SIZE_MISMATCH;
            return jsonify_record_audit_log_exit(s, (struct record_audit_log_exit *)e_common, write_interpreted);
        default:
            // Quietly ignore any expected record.
            return ERR_RECORD_UNKNOWN;
    }
}