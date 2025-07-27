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

#include "user/api/api.h"
#include "user/arg/control.h"


typedef enum
{
    SET = 1,
    GET = 2
} api_control_operation_t;

struct api_control_operation_set
{
    struct control src;
};

struct api_control_operation_get
{
    struct control dst;
};

struct api_control
{
    struct api_header header;
    api_control_operation_t op;
    union {
        struct api_control_operation_set set;
        struct api_control_operation_get get;
    } operation ;
};