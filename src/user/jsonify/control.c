#include <stdlib.h>
#include <stdio.h>
#include "user/jsonify/control.h"


static int jsonify_control_write_trace_mode(struct json_buffer *s, char *key, trace_mode_t t)
{
    char *p = NULL;
    if (t == IGNORE)
    {
        p = "ignore";
    }
    else if (t == CAPTURE)
    {
        p = "capture";
    }
    else
    {
        p = "unknown";
    }
    return jsonify_core_write_str(s, key, p);
}

static int jsonify_control_write_control_lock(struct json_buffer *s, char *key, control_lock_t t)
{
    char *p = NULL;
    if (t == FREE)
    {
        p = "free";
    }
    else if (t == TAKEN)
    {
        p = "taken";
    }
    else
    {
        p = "unknown";
    }
    return jsonify_core_write_str(s, key, p);
}

static int jsonify_control_write_int_list(struct json_buffer *s, char *key, int list[], int len)
{
    char list_str_len = 64;
    char list_str[list_str_len];
    int list_idx = 0;

    list_idx += sprintf(&list_str[list_idx], "[");
    for (int i = 0; i < len; i++)
    {
        list_idx += sprintf(
            &list_str[list_idx],
            "%d%s", list[i], i < len - 1 ? ", " : "");
    }
    list_idx += sprintf(&list_str[list_idx], "]");
    return jsonify_core_write_raw(s, key, &list_str[0]);
}

int jsonify_control_write_control_input(struct json_buffer *s, struct control_input *val)
{
    int total = 0;

    total += jsonify_control_write_trace_mode(s, "global_mode", val->global_mode);
    total += jsonify_control_write_control_lock(s, "lock", val->lock);
    total += jsonify_control_write_trace_mode(s, "netio_mode", val->netio_mode);
    total += jsonify_control_write_trace_mode(s, "pid_mode", val->pid_mode);
    total += jsonify_control_write_trace_mode(s, "ppid_mode", val->ppid_mode);
    total += jsonify_control_write_trace_mode(s, "uid_mode", val->uid_mode);
    total += jsonify_control_write_int_list(s, "pids", &(val->pids[0]), val->pids_len);
    total += jsonify_control_write_int_list(s, "ppids", &(val->ppids[0]), val->ppids_len);
    total += jsonify_control_write_int_list(s, "uids", &(val->uids[0]), val->uids_len);

    return total;
}