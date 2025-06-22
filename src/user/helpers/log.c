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
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#include "user/jsonify/log_msg.h"
#include "user/helpers/log.h"


void __log_state(FILE *out_f, app_state_t state, struct json_buffer *js)
{
    struct log_msg m;
    clock_gettime(CLOCK_REALTIME, &m.ts);
    m.state = state;
    m.json = js;

    int js_msg_buffer_size = 1024;
    char *js_msg_buffer = malloc(sizeof(char) * js_msg_buffer_size);
    if (!js_msg_buffer)
        return;
    memset(js_msg_buffer, 0, js_msg_buffer_size);

    struct json_buffer js_msg;
    jsonify_core_init(&js_msg, js_msg_buffer, js_msg_buffer_size);
    jsonify_core_open_obj(&js_msg);
    jsonify_log_msg_write_log_msg(&js_msg, &m);
    jsonify_core_close_obj(&js_msg);

    fprintf(out_f, "%s\n", js_msg_buffer);

    free(js_msg_buffer);

    fflush(out_f);
}

void log_state(app_state_t state, struct json_buffer *js)
{
    __log_state(stdout, state, js);
}

void log_state_starting(struct json_buffer *js)
{
    log_state(APP_STATE_STARTING, js);
}

void log_state_operational(struct json_buffer *js)
{
    log_state(APP_STATE_OPERATIONAL, js);
}

void log_state_operational_with_error(struct json_buffer *js)
{
    log_state(APP_STATE_OPERATIONAL_WITH_ERROR, js);
}

void log_state_stopped_with_error(struct json_buffer *js)
{
    log_state(APP_STATE_STOPPED_WITH_ERROR, js);
}

void log_state_stopped_normally(struct json_buffer *js)
{
    log_state(APP_STATE_STOPPED_NORMALLY, js);
}
