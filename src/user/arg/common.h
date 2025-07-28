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

#pragma once

/*

    A module to help parse common input from user/config arguments.

*/

#include <argp.h>

#include "user/arg/parse_state.h"

struct arg_common
{
    int show_help;
    int show_usage;
    int show_version;  
};

/*
    Function to initialize to zero.s
*/
void arg_common_init(struct arg_common *a);

/*
    Function to show help and update states.
*/
void arg_common_show_help(struct arg_common *a, struct arg_parse_state *arg_parse_state);

/*
    Function to show usage and update states.
*/
void arg_common_show_usage(struct arg_common *a, struct arg_parse_state *arg_parse_state);

/*
    Function to show version and update states.
*/
void arg_common_show_version(struct arg_common *a, struct arg_parse_state *arg_parse_state);

/*
    Function check if show version, usage or help was set.
*/
int arg_common_is_usage_help_or_version_set(struct arg_common *a);