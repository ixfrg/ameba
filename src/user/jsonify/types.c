#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "user/jsonify/types.h"


int jsonify_types_write_pid(struct json_buffer *s, const char *key, pid_t val)
{
    return jsonify_core_write_int(s, key, val);
}

static int jsonify_types_write_record_type(struct json_buffer *s, const char *key, record_type_t val)
{
    return jsonify_core_write_int(s, key, val);
}

int jsonify_types_write_uid(struct json_buffer *s, const char *key, uid_t val)
{
    return jsonify_core_write_uint(s, key, val);
}

int jsonify_types_write_gid(struct json_buffer *s, const char *key, gid_t val)
{
    return jsonify_core_write_uint(s, key, val);
}

int jsonify_types_write_inode(struct json_buffer *s, const char *key, inode_num_t val)
{
    return jsonify_core_write_uint(s, key, val);
}

int jsonify_types_write_event_id(struct json_buffer *s, event_id_t val)
{
    return jsonify_core_write_ulong(s, "event_id", val);
}

static int jsonify_types_write_version(struct json_buffer *s, const char *key, struct elem_version *version)
{
    const int max_size = 13;
    char local_val[max_size];
    memset(&local_val[0], 0, max_size);

    snprintf(&local_val[0], max_size, "%u.%u.%u", version->major, version->minor, version->patch);

    return jsonify_core_write_str(s, key, &local_val[0]);
}

int jsonify_types_write_sys_id(struct json_buffer *s, sys_id_t sys_id)
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
    return jsonify_core_write_str(s, "sys_id", sys_name);
}

static int jsonify_types_write_elem_sockaddr_raw(struct json_buffer *s, struct elem_sockaddr *sa)
{
    int total = 0;
    total += jsonify_core_write_bytes(s, "sockaddr", &(sa->addr[0]), sa->addrlen);
    total += jsonify_core_write_int(s, "sockaddr_len", sa->addrlen);
    return total;
}

static int jsonify_types_write_ip4_sockaddr_in(struct json_buffer *s, const struct sockaddr_in *sa_in, byte_order_t byte_order)
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
    if (!inet_ntop(AF_INET, &(sa_in->sin_addr), &ip[0], sizeof(ip)))
    {
        strncpy(&ip[0], "ERROR", sizeof("ERROR"));
        port = -1;
    }

    total += jsonify_core_write_str(s, "ip", &ip[0]);
    total += jsonify_core_write_int(s, "port", port);
    return total;
}

static int jsonify_types_write_ip6_sockaddr_in(struct json_buffer *s, const struct sockaddr_in6 *sa_in, byte_order_t byte_order)
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
    if (!inet_ntop(AF_INET6, &(sa_in->sin6_addr), &ip[0], sizeof(ip)))
    {
        strncpy(&ip[0], "ERROR", sizeof("ERROR"));
        port = -1;
    }

    total += jsonify_core_write_str(s, "ip", &ip[0]);
    total += jsonify_core_write_int(s, "port", port);
    return total;
}

static int jsonify_types_write_sockaddr_un(struct json_buffer *s, const struct sockaddr_un *sa_un)
{
    return jsonify_core_write_str(s, "sun_path", &sa_un->sun_path[0]);
}

static int jsonify_types_write_elem_sockaddr_generic(struct json_buffer *s, struct elem_sockaddr *e_sa)
{
    return jsonify_types_write_elem_sockaddr_raw(s, e_sa);
}

int jsonify_types_write_elem_sockaddr(struct json_buffer *s, const char *key, struct elem_sockaddr *e_sa)
{
    char *s_child_buf = (char *)malloc(sizeof(char) * MAX_BUFFER_LEN);
    if (!s_child_buf)
        return 0;

    struct json_buffer s_child;
    jsonify_core_init(&s_child, s_child_buf, MAX_BUFFER_LEN);
    jsonify_core_open_obj(&s_child);

    struct sockaddr *sa = (struct sockaddr *)(e_sa->addr);

    if (sa->sa_family == AF_INET || sa->sa_family == PF_INET)
    {
        const struct sockaddr_in *sa_in = (const struct sockaddr_in *)sa;
        jsonify_types_write_ip4_sockaddr_in(&s_child, sa_in, e_sa->byte_order);
    }
    else if (sa->sa_family == AF_INET6 || sa->sa_family == PF_INET6)
    {
        const struct sockaddr_in6 *sa_in = (const struct sockaddr_in6 *)sa;
        jsonify_types_write_ip6_sockaddr_in(&s_child, sa_in, e_sa->byte_order);
    }
    else if (sa->sa_family == AF_UNIX || sa->sa_family == PF_UNIX)
    {
        const struct sockaddr_un *sa_un = (const struct sockaddr_un *)sa;
        jsonify_types_write_sockaddr_un(&s_child, sa_un);
    }
    else
    {
        jsonify_types_write_elem_sockaddr_generic(&s_child, e_sa);
    }

    jsonify_core_close_obj(&s_child);

    int total = 0;
    total = jsonify_core_write_raw(s, key, &s_child.buf[0]);
    free(s_child_buf);
    return total;
}

static int jsonify_types_write_elem_timestamp(struct json_buffer *s, struct elem_timestamp *e_ts)
{
    int total = 0;
    total += jsonify_types_write_event_id(s, e_ts->event_id);
    return total;
}

int jsonify_types_write_common(
    struct json_buffer *s, struct elem_common *e_common, 
    struct elem_timestamp *e_ts, char *record_type_name
)
{
    int total = 0;
    total += jsonify_core_write_str(s, "record_name", record_type_name);
    total += jsonify_types_write_record_type(s, "record_type", e_common->record_type);
    total += jsonify_types_write_version(s, "record_version", &e_common->version);
    total += jsonify_types_write_elem_timestamp(s, e_ts);
    return total;
}

int jsonify_types_write_fd(struct json_buffer *s, const char *key, int val)
{
    return jsonify_core_write_int(s, key, val);
}

int jsonify_types_write_return(struct json_buffer *s, const char *key, int val)
{
    return jsonify_core_write_int(s, key, val);
}