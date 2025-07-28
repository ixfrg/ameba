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

#define MAX_LIST_ITEMS 10

typedef enum
{
    IGNORE = 1,
    CAPTURE
} control_trace_mode_t;

/*
    See argp_option definition in src/user/arg/control.c
*/
struct control
{
    control_trace_mode_t global_mode;

    control_trace_mode_t uid_mode;
    int uids[MAX_LIST_ITEMS];
    int uids_len;

    control_trace_mode_t pid_mode;
    int pids[MAX_LIST_ITEMS];
    int pids_len;

    control_trace_mode_t ppid_mode;
    int ppids[MAX_LIST_ITEMS];
    int ppids_len;

    control_trace_mode_t netio_mode;
};