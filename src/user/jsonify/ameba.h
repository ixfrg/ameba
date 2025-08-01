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

    A module to help write arg_ameba to json_buffer.

    See 'core.h'.

*/

#include "user/jsonify/core.h"
#include "user/arg/ameba.h"


/*
    Write arg_ameba to json_buffer.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_ameba_write_arg_ameba(struct json_buffer *s, struct arg_ameba *val);

/*
    Write arg_ameba to file.

    Return:
        See 'jsonify_core_snprintf'.
*/
void jsonify_ameba_write_arg_ameba_to_file(FILE *out, struct arg_ameba *val);