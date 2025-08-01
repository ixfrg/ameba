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

#include "user/arg/common.h"
#include "user/jsonify/version.h"


void arg_common_init(struct arg_common *a)
{
    if (!a)
        return;
    a->show_help = 0;
    a->show_usage = 0;
    a->show_version = 0;
}

void arg_common_show_help(struct arg_common *a, struct arg_parse_state *arg_parse_state)
{
    if (!a || !arg_parse_state)
        return;
    a->show_help = 1;
    arg_parse_state_set_exit_no_error(arg_parse_state);
}

void arg_common_show_usage(struct arg_common *a, struct arg_parse_state *arg_parse_state)
{
    if (!a || !arg_parse_state)
        return;
    a->show_usage = 1;
    arg_parse_state_set_exit_no_error(arg_parse_state);
}

void arg_common_show_version(struct arg_common *a, struct arg_parse_state *arg_parse_state)
{
    if (!a || !arg_parse_state)
        return;
    a->show_version = 1;
    arg_parse_state_set_exit_no_error(arg_parse_state);
}

int arg_common_is_usage_help_or_version_set(struct arg_common *a)
{
    if (!a)
        return 0;
    return a->show_help || a->show_usage || a->show_version;
}