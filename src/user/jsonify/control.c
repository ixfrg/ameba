// SPDX-License-Identifier: GPL-3.0-or-later
/*
AMEBA - A Minimal eBPF-based Audit: an eBPF-based Linux telemetry collection tool.
Copyright (C) 2025  Hassaan Irshad

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdio.h>

#include "user/jsonify/control.h"


static int jsonify_control_write_trace_mode(struct json_buffer *s, char *key, control_trace_mode_t t)
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
    return jsonify_core_write_as_literal(s, key, &list_str[0]);
}

int jsonify_control_write_control(struct json_buffer *s, struct control *val)
{
    int total = 0;

    total += jsonify_control_write_trace_mode(s, "global_mode", val->global_mode);
    total += jsonify_control_write_trace_mode(s, "netio_mode", val->netio_mode);
    total += jsonify_control_write_trace_mode(s, "pid_mode", val->pid_mode);
    total += jsonify_control_write_trace_mode(s, "ppid_mode", val->ppid_mode);
    total += jsonify_control_write_trace_mode(s, "uid_mode", val->uid_mode);
    total += jsonify_control_write_int_list(s, "pids", &(val->pids[0]), val->pids_len);
    total += jsonify_control_write_int_list(s, "ppids", &(val->ppids[0]), val->ppids_len);
    total += jsonify_control_write_int_list(s, "uids", &(val->uids[0]), val->uids_len);

    return total;
}

int jsonify_control_write_arg_control(struct json_buffer *s, struct arg_control *arg_val)
{
    struct control *val = &arg_val->control;
    return jsonify_control_write_control(s, val);
}