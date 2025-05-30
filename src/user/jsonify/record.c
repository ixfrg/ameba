#include "user/jsonify/record.h"


int jsonify_record_connect(struct json_buffer *s, struct record_connect *data)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_connect");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_fd(s, "fd", data->fd);
    total += jsonify_types_write_return(s, "ret", data->ret);
    total += jsonify_types_write_elem_sockaddr(s, "local", &(data->local));
    total += jsonify_types_write_elem_sockaddr(s, "remote", &(data->remote));

    return total;
}

int jsonify_record_accept(struct json_buffer *s, struct record_accept *data)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_accept");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_sys_id(s, data->sys_id);
    total += jsonify_types_write_fd(s, "fd", data->fd);
    total += jsonify_types_write_elem_sockaddr(s, "local", &(data->local));
    total += jsonify_types_write_elem_sockaddr(s, "remote", &(data->remote));

    return total;
}

int jsonify_record_namespace(struct json_buffer *s, struct record_namespace *data)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_namespace");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_sys_id(s, data->sys_id);
    total += jsonify_types_write_inode(s, "ns_ipc", data->ns_ipc);
    total += jsonify_types_write_inode(s, "ns_mnt", data->ns_mnt);
    total += jsonify_types_write_inode(s, "ns_pid_children", data->ns_pid_children);
    total += jsonify_types_write_inode(s, "ns_net", data->ns_net);
    total += jsonify_types_write_inode(s, "ns_cgroup", data->ns_cgroup);
    total += jsonify_types_write_inode(s, "ns_usr", data->ns_usr);

    return total;
}

int jsonify_record_new_process(struct json_buffer *s, struct record_new_process *data)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_new_process");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_pid(s, "ppid", data->ppid);
    total += jsonify_types_write_sys_id(s, data->sys_id);
    // total += str_buffer_state_json_write_str(&s, "comm", &data->comm[0]);

    return total;
}

int jsonify_record_cred(struct json_buffer *s, struct record_cred *data)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_cred");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_sys_id(s, data->sys_id);
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

int jsonify_record_send_recv(struct json_buffer *s, struct record_send_recv *data)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_send_recv");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_sys_id(s, data->sys_id);
    total += jsonify_types_write_fd(s, "fd", data->fd);
    total += jsonify_types_write_ssize(s, "ret", data->ret);
    total += jsonify_types_write_elem_sockaddr(s, "local", &(data->local));
    total += jsonify_types_write_elem_sockaddr(s, "remote", &(data->remote));

    return total;
}

int jsonify_record_bind(struct json_buffer *s, struct record_bind *data)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_bind");
    total += jsonify_types_write_pid(s, "pid", data->pid);
    total += jsonify_types_write_fd(s, "fd", data->fd);
    total += jsonify_types_write_elem_sockaddr(s, "local", &(data->local));
    // total += jsonify_types_write_elem_sockaddr(s, "remote", &(data->remote));

    return total;
}

int jsonify_record_kill(struct json_buffer *s, struct record_kill *data)
{
    int total = 0;

    total += jsonify_types_write_common(s, &(data->e_common), &(data->e_ts), "record_kill");
    total += jsonify_types_write_pid(s, "acting_pid", data->acting_pid);
    total += jsonify_core_write_int(s, "sig", data->sig);
    total += jsonify_types_write_pid(s, "target_pid", data->target_pid);
    total += jsonify_types_write_return(s, "ret", data->ret);

    return total;
}