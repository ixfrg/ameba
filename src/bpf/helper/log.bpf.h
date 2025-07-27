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

    A module for defining helper functions for logging.

*/

#include "common/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common/control.h"


// Log prefix.
#define LOG_PREFIX "[ameba] [bpf]"

// Macros for using bpf_printk in a uniform way.
#define LOG_WARN(fmt, args...) bpf_printk("%s" "[WARN]" fmt "\n", LOG_PREFIX, ##args)
#define LOG_ERROR(fmt, args...) bpf_printk("%s" "[ERROR]" fmt "\n", LOG_PREFIX, ##args)

/*
    Log interpreted value of trace mode.

    Return:
        0 -> Always
*/
int log_trace_mode(char *key, control_trace_mode_t t);

/*
    Log interpreted value of control lock with key.

    Return:
        0 -> Always
*/
int log_control_lock(char *key, control_lock_t t);

/*
    Log control_input.

    Return:
        0 -> Always
*/
int log_control(struct control *ctrl);