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

#include "user/args/helper.h"


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