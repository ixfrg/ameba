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

#include <stdio.h>
#include <unistd.h>

#include "user/jsonify/version.h"
#include "user/args/helper.h"


extern const struct elem_version app_version;
extern const struct elem_version record_version;


void user_args_helper_state_init(struct arg_parse_state *s)
{
    if (!s)
        return;
    s->exit = 0;
    s->code = 0;
}

void user_args_helper_state_set_exit_error(struct arg_parse_state *s, int code)
{
    if (!s)
        return;
    s->exit = 1;
    s->code = code;
}

void user_args_helper_state_set_exit_no_error(struct arg_parse_state *s)
{
    if (!s)
        return;
    s->exit = 1;
    s->code = 0;
}

void user_args_helper_state_set_no_exit(struct arg_parse_state *s)
{
    user_args_helper_state_init(s);
}

int user_args_helper_state_is_exit_set(struct arg_parse_state *s)
{
    if (!s)
        return 0;
    return s->exit;
}

int user_args_helper_state_get_code(struct arg_parse_state *s)
{
    if (!s)
        return 0;
    return s->code;
}

void user_args_helper_print_app_version()
{
    int dst_len = 512;
    char dst[dst_len];

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    jsonify_version_write_all_versions(&s);

    jsonify_core_close_obj(&s);

    fprintf(stdout, "%s\n", &dst[0]);
}