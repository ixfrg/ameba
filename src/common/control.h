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

    A module for defining control_input i.e. the input to the BPF
    programs to control the tracing of events.

*/


#include "user/args/helper.h"


#define MAX_LIST_ITEMS 10

typedef enum
{
    FREE = 1,
    TAKEN = 2
} control_lock_t;

typedef enum
{
    IGNORE = 1,
    CAPTURE
} trace_mode_t;

/*
    See argp_option definition in src/user/args/control.c
*/
struct control_input
{
    trace_mode_t global_mode;

    trace_mode_t uid_mode;
    int uids[MAX_LIST_ITEMS];
    int uids_len;

    trace_mode_t pid_mode;
    int pids[MAX_LIST_ITEMS];
    int pids_len;

    trace_mode_t ppid_mode;
    int ppids[MAX_LIST_ITEMS];
    int ppids_len;

    trace_mode_t netio_mode;

    struct arg_parse_state parse_state;
};