#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "user/error.h"

#include "user/jsonify.h"


static void str_buffer_state_init_from_existing_buffer(struct str_buffer_state *s, char *dst, unsigned int dst_len)
{
    s->buf = dst;
    s->maxBufLen = dst_len - 1;
    s->bufIdx = 0;
    s->remBufLen = s->maxBufLen - s->bufIdx;
    memset(&(s->buf[0]), 0, s->maxBufLen);
}

static void str_buffer_state_init_json_obj_from_existing_buffer(struct str_buffer_state *s, char *dst, unsigned int dst_len)
{
    str_buffer_state_init_from_existing_buffer(s, dst, dst_len);
}

static int str_buffer_state_snprintf(struct str_buffer_state *s, const char *format, ...)
{
    va_list args;
    int charsWritten;

    if (s->remBufLen == 0)
    {
        return 0;
    }

    va_start(args, format);

    charsWritten = vsnprintf(&(s->buf[s->bufIdx]), s->remBufLen, format, args);
    if (charsWritten >= s->remBufLen)
    {
        s->remBufLen = 0;
        va_end(args);
        return charsWritten;
    }
    else
    {
        s->remBufLen -= charsWritten;
        s->bufIdx += charsWritten;
        va_end(args);
        return charsWritten;
    }
}

// static int str_buffer_state_is_full(struct str_buffer_state *s){
//     return s->remBufLen == 0;
// }

static int str_buffer_state_json_obj_open(struct str_buffer_state *s)
{
    return str_buffer_state_snprintf(s, "{");
}

static int str_buffer_state_json_obj_close(struct str_buffer_state *s)
{
    return str_buffer_state_snprintf(s, "}");
}

static int str_buffer_state_json_write_bytes(struct str_buffer_state *s, const char *key, unsigned char *val, int val_size)
{
    int total = 0;
    if (s->bufIdx > 1)
        total += str_buffer_state_snprintf(s, ",");
    total += str_buffer_state_snprintf(s, "\"%s\":\"", key);
    for (size_t i = 0; i < val_size; i++)
    {
        total += str_buffer_state_snprintf(s, "%02x", val[i]);
    }
    total += str_buffer_state_snprintf(s, "\"");
    return total;
}

static int str_buffer_state_json_write_int(struct str_buffer_state *s, const char *key, int val)
{
    int total = 0;
    if (s->bufIdx > 1)
        total += str_buffer_state_snprintf(s, ",");
    total += str_buffer_state_snprintf(s, "\"%s\":%d", key, val);
    return total;
}

static int str_buffer_state_json_write_pid(struct str_buffer_state *s, const char *key, pid_t val){
    return str_buffer_state_json_write_int(s, key, val);
}

static int str_buffer_state_json_write_record_type(struct str_buffer_state *s, const char *key, record_type_t val)
{
    return str_buffer_state_json_write_int(s, key, val);
}

static int str_buffer_state_json_write_uint(
    struct str_buffer_state *s, const char *key, unsigned int val
)
{
    int total = 0;
    if (s->bufIdx > 1)
        total += str_buffer_state_snprintf(s, ",");
    total += str_buffer_state_snprintf(s, "\"%s\":%u", key, val);
    return total;
}

static int str_buffer_state_json_write_uid(
    struct str_buffer_state *s, const char *key, uid_t val
)
{
    return str_buffer_state_json_write_uint(s, key, val);
}

static int str_buffer_state_json_write_gid(
    struct str_buffer_state *s, const char *key, gid_t val
)
{
    return str_buffer_state_json_write_uint(s, key, val);
}

static int str_buffer_state_json_write_inode(
    struct str_buffer_state *s, const char *key, inode_num_t val
)
{
    return str_buffer_state_json_write_uint(s, key, val);
}

// static int str_buffer_state_json_write_uint(struct str_buffer_state *s, const char *key, unsigned int val)
// {
//     int total = 0;
//     if (s->bufIdx > 1)
//         total += str_buffer_state_snprintf(s, ",");
//     total += str_buffer_state_snprintf(s, "\"%s\":%u", key, val);
//     return total;
// }

static int str_buffer_state_json_write_str(struct str_buffer_state *s, const char *key, const char *val)
{
    int total = 0;
    if (s->bufIdx > 1)
        total += str_buffer_state_snprintf(s, ",");
    total += str_buffer_state_snprintf(s, "\"%s\":\"%s\"", key, val);
    return total;
}

static int str_buffer_state_json_write_raw(struct str_buffer_state *s, const char *key, const char *val)
{
    int total = 0;
    if (s->bufIdx > 1)
        total += str_buffer_state_snprintf(s, ",");
    total += str_buffer_state_snprintf(s, "\"%s\":%s", key, val);
    return total;
}

static int str_buffer_state_json_write_ulong(struct str_buffer_state *s, const char *key, unsigned long val)
{
    int total = 0;
    if (s->bufIdx > 1)
        total += str_buffer_state_snprintf(s, ",");
    total += str_buffer_state_snprintf(s, "\"%s\":%lu", key, val);
    return total;
}

static int str_buffer_state_json_write_event_id(struct str_buffer_state *s, const char *key, event_id_t val)
{
    return str_buffer_state_json_write_ulong(s, key, val);
}

static int str_buffer_state_json_write_version(
    struct str_buffer_state *s, const char *key, struct elem_version *version
)
{
    int total = 0;
    if (s->bufIdx > 1)
        total += str_buffer_state_snprintf(s, ",");
    total += str_buffer_state_snprintf(
        s, "\"%s\":\"%u.%u.%u\"", key, version->major, version->minor, version->patch
    );
    return total;
}

// static int str_buffer_state_json_write_long(struct str_buffer_state *s, const char *key, long val)
// {
//     int total = 0;
//     if (s->bufIdx > 1)
//         total += str_buffer_state_snprintf(s, ",");
//     total += str_buffer_state_snprintf(s, "\"%s\":%ld", key, val);
//     return total;
// }

static int str_buffer_state_json_write_sys_id(
    struct str_buffer_state *s, const char *key, sys_id_t sys_id
)
{
    char *sys_name;
    switch (sys_id)
    {
    case SYS_ID_FORK:
        sys_name = "fork";
        break;
    case SYS_ID_VFORK:
        sys_name = "vfork";
        break;
    case SYS_ID_CLONE:
        sys_name = "clone";
        break;
    case SYS_ID_SETNS:
        sys_name = "setns";
        break;
    case SYS_ID_UNSHARE:
        sys_name = "unshare";
        break;
    default:
        sys_name = "UNKNOWN";
        break;
    }
    return str_buffer_state_json_write_str(s, key, sys_name);
}

static int str_buffer_state_json_write_elem_sockaddr_raw(struct str_buffer_state *s, struct elem_sockaddr *sa)
{
    int total = 0;
    total += str_buffer_state_json_write_bytes(s, "sockaddr", &(sa->addr[0]), sa->addrlen);
    total += str_buffer_state_json_write_int(s, "sockaddr_len", sa->addrlen);
    return total;
}

static int str_buffer_state_json_write_ip4_sockaddr_in(
    struct str_buffer_state *s, const struct sockaddr_in *sa_in, byte_order_t byte_order
)
{
    int total = 0;
    int port;
    char ip[INET_ADDRSTRLEN];

    port = sa_in->sin_port;
    switch (byte_order)
    {
        case BYTE_ORDER_NETWORK:
            port = ntohs(port);
            break;
        default:
            break;
    }
    if (inet_ntop(AF_INET, &(sa_in->sin_addr), &ip[0], sizeof(ip)) == NULL)
    {
        strncpy(&ip[0], "ERROR", sizeof("ERROR"));
        port = -1;
    }

    total += str_buffer_state_json_write_str(s, "ip", &ip[0]);
    total += str_buffer_state_json_write_int(s, "port", port);
    return total;
}

static int str_buffer_state_json_write_ip6_sockaddr_in(
    struct str_buffer_state *s, const struct sockaddr_in6 *sa_in, byte_order_t byte_order
)
{
    int total = 0;
    int port;
    char ip[INET6_ADDRSTRLEN];

    port = sa_in->sin6_port;
    switch (byte_order)
    {
        case BYTE_ORDER_NETWORK:
            port = ntohs(port);
            break;
        default:
            break;
    }
    if (inet_ntop(AF_INET6, &(sa_in->sin6_addr), &ip[0], sizeof(ip)) == NULL)
    {
        strncpy(&ip[0], "ERROR", sizeof("ERROR"));
        port = -1;
    }

    total += str_buffer_state_json_write_str(s, "ip", &ip[0]);
    total += str_buffer_state_json_write_int(s, "port", port);
    return total;
}

static int str_buffer_state_json_write_sockaddr_un(struct str_buffer_state *s, const struct sockaddr_un *sa_un)
{
    return str_buffer_state_json_write_str(s, "path", &sa_un->sun_path[0]);
    // str_buffer_state_json_write_record_sockaddr_raw(s, r_sa);
}

static int str_buffer_state_json_write_elem_sockaddr_generic(struct str_buffer_state *s, struct elem_sockaddr *e_sa)
{
    return str_buffer_state_json_write_elem_sockaddr_raw(s, e_sa);
}

static int str_buffer_state_json_write_elem_sockaddr(
    struct str_buffer_state *s, const char *key, struct elem_sockaddr *e_sa
)
{
    char *s_child_buf = (char *)malloc(sizeof(char) * MAX_BUFFER_LEN);
    if (s_child_buf == NULL)
        return 0;

    struct str_buffer_state s_child;
    str_buffer_state_init_json_obj_from_existing_buffer(&s_child, s_child_buf, MAX_BUFFER_LEN);
    str_buffer_state_json_obj_open(&s_child);

    struct sockaddr *sa = (struct sockaddr *)(e_sa->addr);

    if (sa->sa_family == AF_INET || sa->sa_family == PF_INET)
    {
        const struct sockaddr_in *sa_in = (const struct sockaddr_in *)sa;
        str_buffer_state_json_write_ip4_sockaddr_in(&s_child, sa_in, e_sa->byte_order);
    }
    else if (sa->sa_family == AF_INET6 || sa->sa_family == PF_INET6)
    {
        const struct sockaddr_in6 *sa_in = (const struct sockaddr_in6 *)sa;
        str_buffer_state_json_write_ip6_sockaddr_in(&s_child, sa_in, e_sa->byte_order);
    }
    else if (sa->sa_family == AF_UNIX || sa->sa_family == PF_UNIX)
    {
        const struct sockaddr_un *sa_un = (const struct sockaddr_un *)sa;
        str_buffer_state_json_write_sockaddr_un(&s_child, sa_un);
    }
    else
    {
        str_buffer_state_json_write_elem_sockaddr_generic(&s_child, e_sa);
    }

    str_buffer_state_json_obj_close(&s_child);

    int total = 0;
    total = str_buffer_state_json_write_raw(s, key, &s_child.buf[0]);
    free(s_child_buf);
    return total;
}

static int str_buffer_state_json_write_elem_common(
    struct str_buffer_state *s,
    struct elem_common *e_common,
    char *record_type_name)
{
    int total = 0;
    total += str_buffer_state_json_write_str(s, "type_name", record_type_name);
    total += str_buffer_state_json_write_record_type(s, "type_id", e_common->record_type);
    total += str_buffer_state_json_write_version(s, "version", &e_common->version);
    return total;
}

static int str_buffer_state_json_write_elem_timestamp(
    struct str_buffer_state *s,
    struct elem_timestamp *e_ts
)
{
    int total = 0;
    total += str_buffer_state_json_write_event_id(s, "event_id", e_ts->event_id);
    return total;
}

static int record_connect_to_json(char *dst, unsigned int dst_len, struct record_connect *data, char *record_type_name)
{
    int total = 0;

    struct str_buffer_state s;
    str_buffer_state_init_json_obj_from_existing_buffer(&s, dst, dst_len);
    str_buffer_state_json_obj_open(&s);

    total += str_buffer_state_json_write_elem_common(&s, &(data->e_common), record_type_name);
    total += str_buffer_state_json_write_elem_timestamp(&s, &(data->e_ts));
    total += str_buffer_state_json_write_pid(&s, "pid", data->pid);
    total += str_buffer_state_json_write_int(&s, "fd", data->fd);
    total += str_buffer_state_json_write_int(&s, "ret", data->ret);
    total += str_buffer_state_json_write_elem_sockaddr(&s, "local", &(data->local));
    total += str_buffer_state_json_write_elem_sockaddr(&s, "remote", &(data->remote));

    str_buffer_state_json_obj_close(&s);

    return total;
}

static int record_accept_to_json(char *dst, unsigned int dst_len, struct record_accept *data, char *record_type_name)
{
    int total = 0;

    struct str_buffer_state s;
    str_buffer_state_init_json_obj_from_existing_buffer(&s, dst, dst_len);
    str_buffer_state_json_obj_open(&s);

    total += str_buffer_state_json_write_elem_common(&s, &(data->e_common), record_type_name);
    total += str_buffer_state_json_write_elem_timestamp(&s, &(data->e_ts));
    total += str_buffer_state_json_write_pid(&s, "pid", data->pid);
    total += str_buffer_state_json_write_int(&s, "fd", data->fd);
    total += str_buffer_state_json_write_elem_sockaddr(&s, "local", &(data->local));
    total += str_buffer_state_json_write_elem_sockaddr(&s, "remote", &(data->remote));

    str_buffer_state_json_obj_close(&s);

    return total;
}

static int record_namespace_to_json(
    char *dst, unsigned int dst_len, struct record_namespace *data, char *record_type_name
)
{
    int total = 0;

    struct str_buffer_state s;
    str_buffer_state_init_json_obj_from_existing_buffer(&s, dst, dst_len);
    str_buffer_state_json_obj_open(&s);

    total += str_buffer_state_json_write_elem_common(&s, &(data->e_common), record_type_name);
    total += str_buffer_state_json_write_elem_timestamp(&s, &(data->e_ts));
    total += str_buffer_state_json_write_pid(&s, "pid", data->pid);
    total += str_buffer_state_json_write_sys_id(&s, "sys_id", data->sys_id);
    total += str_buffer_state_json_write_inode(&s, "ns_ipc", data->ns_ipc);
    total += str_buffer_state_json_write_inode(&s, "ns_mnt", data->ns_mnt);
    total += str_buffer_state_json_write_inode(&s, "ns_pid_children", data->ns_pid_children);
    total += str_buffer_state_json_write_inode(&s, "ns_net", data->ns_net);
    total += str_buffer_state_json_write_inode(&s, "ns_cgroup", data->ns_cgroup);
    total += str_buffer_state_json_write_inode(&s, "ns_usr", data->ns_usr);

    str_buffer_state_json_obj_close(&s);

    return total;
}

static int record_new_process_to_json(char *dst, unsigned int dst_len, struct record_new_process *data, char *record_type_name)
{
    int total = 0;

    struct str_buffer_state s;
    str_buffer_state_init_json_obj_from_existing_buffer(&s, dst, dst_len);
    str_buffer_state_json_obj_open(&s);

    total += str_buffer_state_json_write_elem_common(&s, &(data->e_common), record_type_name);
    total += str_buffer_state_json_write_elem_timestamp(&s, &(data->e_ts));
    total += str_buffer_state_json_write_pid(&s, "pid", data->pid);
    total += str_buffer_state_json_write_pid(&s, "ppid", data->ppid);
    total += str_buffer_state_json_write_sys_id(&s, "sys_id", data->sys_id);
    // total += str_buffer_state_json_write_str(&s, "comm", &data->comm[0]);

    str_buffer_state_json_obj_close(&s);

    return total;
}

static int record_cred_to_json(char *dst, unsigned int dst_len, struct record_cred *data, char *record_type_name)
{
    int total = 0;

    struct str_buffer_state s;
    str_buffer_state_init_json_obj_from_existing_buffer(&s, dst, dst_len);
    str_buffer_state_json_obj_open(&s);

    total += str_buffer_state_json_write_elem_common(&s, &(data->e_common), record_type_name);
    total += str_buffer_state_json_write_elem_timestamp(&s, &(data->e_ts));
    total += str_buffer_state_json_write_pid(&s, "pid", data->pid);
    total += str_buffer_state_json_write_sys_id(&s, "sys_id", data->sys_id);
    total += str_buffer_state_json_write_uid(&s, "uid", data->uid);
    total += str_buffer_state_json_write_uid(&s, "euid", data->euid);
    total += str_buffer_state_json_write_uid(&s, "suid", data->suid);
    total += str_buffer_state_json_write_uid(&s, "fsuid", data->fsuid);
    total += str_buffer_state_json_write_gid(&s, "gid", data->gid);
    total += str_buffer_state_json_write_gid(&s, "egid", data->egid);
    total += str_buffer_state_json_write_gid(&s, "sgid", data->sgid);
    total += str_buffer_state_json_write_gid(&s, "fsgid", data->fsgid);

    str_buffer_state_json_obj_close(&s);

    return total;
}

int jsonify_record_data_to_json(char *dst, unsigned int dst_len, void *data, size_t data_len)
{
    if (dst == NULL)
        return ERR_DST_INVALID;
    if (dst_len == 0)
        return ERR_DST_INSUFFICIENT;
    if (data == NULL)
        return ERR_DATA_INVALID;
    if (data_len == 0)
        return ERR_DATA_INVALID;

    if (data_len < sizeof(struct elem_common))
        return ERR_DATA_INVALID_HEADER;

    struct elem_common *e_common = (struct elem_common *)(data);

    if (e_common->magic != AMEBA_MAGIC)
        return ERR_DATA_INVALID_MAGIC;

    switch (e_common->record_type)
    {
        case RECORD_TYPE_CONNECT:
            if (data_len != sizeof(struct record_connect))
                return ERR_DATA_SIZE_MISMATCH;
            return record_connect_to_json(dst, dst_len, (struct record_connect *)data, "record_connect");
        case RECORD_TYPE_ACCEPT:
            if (data_len != sizeof(struct record_accept))
                return ERR_DATA_SIZE_MISMATCH;
            return record_accept_to_json(dst, dst_len, (struct record_accept *)data, "record_accept");
        case RECORD_TYPE_NAMESPACE:
            if (data_len != sizeof(struct record_namespace))
                return ERR_DATA_SIZE_MISMATCH;
            return record_namespace_to_json(dst, dst_len, (struct record_namespace *)data, "record_namespace");
        case RECORD_TYPE_NEW_PROCESS:
            if (data_len != sizeof(struct record_new_process))
                return ERR_DATA_SIZE_MISMATCH;
            return record_new_process_to_json(dst, dst_len, (struct record_new_process *)data, "record_new_process");
        case RECORD_TYPE_CRED:
            if (data_len != sizeof(struct record_cred))
                return ERR_DATA_SIZE_MISMATCH;
            return record_cred_to_json(dst, dst_len, (struct record_cred *)data, "record_cred");
        default:
            // Quietly ignore any expected record.
            return ERR_DATA_UNKNOWN;
    }
}