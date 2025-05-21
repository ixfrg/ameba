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

#include "jsonify_record.h"


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

// static int str_buffer_state_json_write_long(struct str_buffer_state *s, const char *key, long val)
// {
//     int total = 0;
//     if (s->bufIdx > 1)
//         total += str_buffer_state_snprintf(s, ",");
//     total += str_buffer_state_snprintf(s, "\"%s\":%ld", key, val);
//     return total;
// }

// static int str_buffer_state_json_write_syscall(struct str_buffer_state *s, int sys_id)
// {
//     int total = 0;
//     if (s->bufIdx > 1)
//         total += str_buffer_state_snprintf(s, ",");
//     char *sys_name;
//     switch (sys_id)
//     {
//     case SYS_ID_FORK:
//         sys_name = "fork";
//         break;
//     case SYS_ID_VFORK:
//         sys_name = "vfork";
//         break;
//     case SYS_ID_CLONE:
//         sys_name = "clone";
//         break;
//     case SYS_ID_SETNS:
//         sys_name = "setns";
//         break;
//     case SYS_ID_UNSHARE:
//         sys_name = "unshare";
//         break;
//     default:
//         sys_name = "UNKNOWN";
//         break;
//     }
//     total += str_buffer_state_snprintf(s, "\"%s\":\"%s\"", "syscall", sys_name);
//     return total;
// }

static int str_buffer_state_json_write_elem_sockaddr_raw(struct str_buffer_state *s, struct elem_sockaddr *sa)
{
    int total = 0;
    total += str_buffer_state_json_write_bytes(s, "sockaddr", &(sa->addr[0]), sa->addrlen);
    total += str_buffer_state_json_write_int(s, "sockaddr_len", sa->addrlen);
    return total;
}

static int str_buffer_state_json_write_ip4_sockaddr_in(struct str_buffer_state *s, const struct sockaddr_in *sa_in, int do_ntohs)
{
    int total = 0;
    int port;
    char ip[INET_ADDRSTRLEN];

    port = sa_in->sin_port;
    if (do_ntohs)
        port = ntohs(port);
    if (inet_ntop(AF_INET, &(sa_in->sin_addr), &ip[0], sizeof(ip)) == NULL)
    {
        strncpy(&ip[0], "ERROR", sizeof("ERROR"));
        port = -1;
    }

    total += str_buffer_state_json_write_str(s, "ip", &ip[0]);
    total += str_buffer_state_json_write_int(s, "port", port);
    return total;
}

static int str_buffer_state_json_write_ip6_sockaddr_in(struct str_buffer_state *s, const struct sockaddr_in6 *sa_in, int do_ntohs)
{
    int total = 0;
    int port;
    char ip[INET6_ADDRSTRLEN];

    port = sa_in->sin6_port;
    if (do_ntohs)
        port = ntohs(port);
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

static int str_buffer_state_json_write_elem_sockaddr(struct str_buffer_state *s, const char *key, struct elem_sockaddr *e_sa, int do_ntohs)
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
        str_buffer_state_json_write_ip4_sockaddr_in(&s_child, sa_in, do_ntohs);
    }
    else if (sa->sa_family == AF_INET6 || sa->sa_family == PF_INET6)
    {
        const struct sockaddr_in6 *sa_in = (const struct sockaddr_in6 *)sa;
        str_buffer_state_json_write_ip6_sockaddr_in(&s_child, sa_in, do_ntohs);
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
    total += str_buffer_state_json_write_int(s, "type_id", e_common->record_type_id);
    total += str_buffer_state_json_write_ulong(s, "event_id", e_common->event_id);
    return total;
}

static int record_connect_to_json(char *dst, unsigned int dst_len, struct record_connect *data, char *record_type_name)
{
    int total = 0;

    struct str_buffer_state s;
    str_buffer_state_init_json_obj_from_existing_buffer(&s, dst, dst_len);
    str_buffer_state_json_obj_open(&s);

    total += str_buffer_state_json_write_elem_common(&s, &(data->e_common), record_type_name);
    total += str_buffer_state_json_write_int(&s, "fd", data->fd);
    total += str_buffer_state_json_write_int(&s, "ret", data->ret);
    total += str_buffer_state_json_write_int(&s, "pid", data->pid);
    total += str_buffer_state_json_write_elem_sockaddr(&s, "local", &(data->local), 0);
    total += str_buffer_state_json_write_elem_sockaddr(&s, "remote", &(data->remote), 1);

    str_buffer_state_json_obj_close(&s);

    return total;
}

int record_data_to_json(char *dst, unsigned int dst_len, void *data, size_t data_len)
{
    if (dst == NULL)
        return -1;
    if (dst_len == 0)
        return -2;
    if (data == NULL)
        return -3;
    if (data_len == 0)
        return -4;
    // Or use a magic number.
    // There should at least be a record type which is int.
    if (data_len < sizeof(int))
        return -5;

    int record_type_id = *((int *)data);
    switch (record_type_id)
    {
        case RECORD_TYPE_CONNECT:
            if (data_len != sizeof(struct record_connect))
            {
                return -6;
            }
            return record_connect_to_json(dst, dst_len, (struct record_connect *)data, "record_connect");
        default:
            // Quietly ignore any expected record.
            return -7;
    }
    
}