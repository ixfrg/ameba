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


#define TEXT_SIZE 1024


typedef enum
{
    STARTING = 1,
    OPERATIONAL = 2,
    OPERATIONAL_WITH_ERROR = 3,
    STOPPED_WITH_ERROR = 4,
    STOPPED_NORMALLY = 5
} state_t;


struct msg
{
    struct timespec ts;
    state_t state;
    char json_text[TEXT_SIZE];
};


void __log(FILE *out_f, state_t state, struct json_buffer *js);


#define log_starting(js) __log(stdout, STARTING, js)
#define log_operational(js) __log(stdout, OPERATIONAL, js)
#define log_operational_with_error(js) __log(stdout, OPERATIONAL_WITH_ERROR, js)
#define log_stopped_with_error(js) __log(stdout, STOPPED_WITH_ERROR, js)
#define log_stopped_normally(js) __log(stdout, STOPPED_NORMALLY, js)