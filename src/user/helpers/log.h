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

#include <stdio.h>

#include "user/jsonify/core.h"


typedef enum
{
    STATE_STARTING = 1,
    STATE_OPERATIONAL = 2,
    STATE_OPERATIONAL_WITH_ERROR = 3,
    STATE_STOPPED_WITH_ERROR = 4,
    STATE_STOPPED_NORMALLY = 5
} state_t;


struct msg
{
    struct timespec ts;
    state_t state;
    struct json_buffer *json;
};


void __log_state(FILE *out_f, state_t state, struct json_buffer *js);

void log_state(state_t state, struct json_buffer *js);

void log_state_starting(struct json_buffer *js);
void log_state_operational(struct json_buffer *js);
void log_state_operational_with_error(struct json_buffer *js);
void log_state_stopped_with_error(struct json_buffer *js);
void log_state_stopped_normally(struct json_buffer *js);
