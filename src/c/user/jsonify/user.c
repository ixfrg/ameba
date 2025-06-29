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
#include "user/jsonify/types.h"
#include "user/jsonify/control.h"
#include "user/jsonify/user.h"


int jsonify_user_write_output_file(struct json_buffer *s, struct output_file *o_file)
{
    int s_child_buf_size = PATH_MAX + 50;
    char s_child_buf[s_child_buf_size];
    struct json_buffer s_child;
    jsonify_core_init(&s_child, &(s_child_buf[0]), s_child_buf_size);
    jsonify_core_open_obj(&s_child);
    jsonify_core_write_str(&s_child, "path", o_file->path);
    jsonify_core_close_obj(&s_child);

    int total = 0;

    char *s_child_buf_ptr;
    int s_child_buf_ptr_size;
    if (jsonify_core_get_internal_buf_ptr(&s_child, &s_child_buf_ptr, &s_child_buf_ptr_size) == 0)
    {
        total = jsonify_core_write_as_literal(s, "output_file", s_child_buf_ptr);
    }

    return total;
}

int jsonify_user_write_output_net(struct json_buffer *s, struct output_net *o_net)
{
    int s_child_buf_size = 256;
    char s_child_buf[s_child_buf_size];
    struct json_buffer s_child;
    jsonify_core_init(&s_child, &(s_child_buf[0]), s_child_buf_size);
    jsonify_core_open_obj(&s_child);
    jsonify_core_write_str(&s_child, "ip", o_net->ip);
    jsonify_core_write_int(&s_child, "port", o_net->port);
    jsonify_types_write_ip_family_name(&s_child, "ip_family", o_net->ip_family);
    jsonify_core_close_obj(&s_child);


    int total = 0; 

    char *s_child_buf_ptr;
    int s_child_buf_ptr_size;
    if (jsonify_core_get_internal_buf_ptr(&s_child, &s_child_buf_ptr, &s_child_buf_ptr_size) == 0)
    {
        total += jsonify_core_write_as_literal(s, "output_net", s_child_buf_ptr);
    }
    
    return total;
}

int jsonify_user_write_output(struct json_buffer *s, struct user_input *val)
{
    int total = 0;
    char *v;
    switch (val->o_type)
    {
        case OUTPUT_NONE:
            v = "none";
            break;
        case OUTPUT_FILE:
            total += jsonify_user_write_output_file(s, &(val->output_file));
            v = "file";
            break;
        case OUTPUT_NET:
            total += jsonify_user_write_output_net(s, &(val->output_net));
            v = "net";
            break;
        default:
            v = "unknown";
            break;
    }
    total += jsonify_core_write_str(s, "output_type", v);
    return total;
}

int jsonify_user_write_user_input(struct json_buffer *s, struct user_input *val)
{
    int s_child_buf_size = 256;
    char s_child_buf[s_child_buf_size];
    struct json_buffer s_child;
    jsonify_core_init(&s_child, &(s_child_buf[0]), s_child_buf_size);
    jsonify_core_open_obj(&s_child);
    jsonify_control_write_control_input(&s_child, &(val->c_in));
    jsonify_core_close_obj(&s_child);

    int total = 0;

    char *s_child_buf_ptr;
    int s_child_buf_ptr_size;
    if (jsonify_core_get_internal_buf_ptr(&s_child, &s_child_buf_ptr, &s_child_buf_ptr_size) == 0)
    {
        total = jsonify_core_write_as_literal(s, "control_input", s_child_buf_ptr);
    }

    total += jsonify_user_write_output(s, val);
    return total;
}