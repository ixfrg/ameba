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

#include "user/jsonify/log_msg.h"


static int jsonify_log_msg_write_app_state_name(struct json_buffer *s, char *key, app_state_t st)
{
    char *name;
    switch (st)
    {
        case APP_STATE_STARTING:
            name = "STARTING";
            break;
        case APP_STATE_OPERATIONAL:
            name = "OPERATIONAL";
            break;
        case APP_STATE_OPERATIONAL_WITH_ERROR:
            name = "OPERATIONAL_WITH_ERROR";
            break;
        case APP_STATE_STOPPED_WITH_ERROR:
            name = "STOPPED_WITH_ERROR";
            break;
        case APP_STATE_STOPPED_NORMALLY:
            name = "STOPPED_NORMALLY";
            break;
        default:
            name = "UNKNOWN";
            break;
    }
    return jsonify_core_write_str(s, key, name);
}


int jsonify_log_msg_write_log_msg(struct json_buffer *s, struct log_msg *val)
{
    int total = 0;

    total += jsonify_core_write_timespec64(s, "time", val->ts.tv_sec, val->ts.tv_nsec);
    total += jsonify_log_msg_write_app_state_name(s, "state_name", val->state);

    char *s_child_buf_ptr;
    int s_child_buf_ptr_size;
    if (jsonify_core_get_internal_buf_ptr(val->json, &s_child_buf_ptr, &s_child_buf_ptr_size) == 0)
    {
        total += jsonify_core_write_as_literal(s, "json", s_child_buf_ptr);
    }

    return total;
}