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

#include "user/args/state.h"

/*
    Initialize to normal state.
*/
void user_args_parse_state_init(struct args_parse_state *s)
{
    if (!s)
        return;
    s->exit = 0;
    s->code = 0;
}

/*
    Set the error code, and corresponding state.
*/
void user_args_parse_state_set_exit_error(struct args_parse_state *s, int code)
{
    if (!s)
        return;
    s->exit = 1;
    s->code = code;
}

/*
    Set exit to true.
*/
void user_args_parse_state_set_exit_no_error(struct args_parse_state *s)
{
    if (!s)
        return;
    s->exit = 1;
    s->code = 0;
}

/*
    Set exit to false.
*/
void user_args_parse_state_set_no_exit(struct args_parse_state *s)
{
    user_args_parse_state_init(s);
}

/*
    Function to check if exit is set.
*/
int user_args_parse_state_is_exit_set(struct args_parse_state *s)
{
    if (!s)
        return 0;
    return s->exit;
}

/*
    Get the exit code.
*/
int user_args_parse_state_get_code(struct args_parse_state *s)
{
    if (!s)
        return 0;
    return s->code;
}