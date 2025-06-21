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

#define _POSIX_C_SOURCE 200809L
#include <time.h>

#include <linux/limits.h>
#include <netinet/in.h>

#include "common/control.h"

#include "user/jsonify/core.h"


typedef enum
{
    APP_STATE_STARTING = 1,
    APP_STATE_OPERATIONAL = 2,
    APP_STATE_OPERATIONAL_WITH_ERROR = 3,
    APP_STATE_STOPPED_WITH_ERROR = 4,
    APP_STATE_STOPPED_NORMALLY = 5
} app_state_t;


struct log_msg
{
    struct timespec ts;
    app_state_t state;
    struct json_buffer *json;
};


struct output_file
{
    char path[PATH_MAX];
};


struct output_net
{
    int ip_family;
    char ip[INET6_ADDRSTRLEN];
    int port;
};


enum output_type {
    OUTPUT_NONE,
    OUTPUT_FILE,
    OUTPUT_NET
};


struct user_input
{
    struct control_input c_in;
    struct output_file output_file;
    struct output_net output_net;
    enum output_type o_type;
};