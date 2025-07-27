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

#include <stdlib.h>
#include <stdio.h>
#include "user/jsonify/core.h"
#include "user/jsonify/ameba.h"


int jsonify_ameba_write_arg_ameba(struct json_buffer *s, struct arg_ameba *val)
{
    int total = 0;

    total += jsonify_core_write_str(s, "log_dir_path", val->log_dir_path);
    total += jsonify_core_write_ulonglong(s, "log_file_size_bytes", val->log_file_size_bytes);
    total += jsonify_core_write_uint(s, "log_file_count", val->log_file_count);

    return total;
}

void jsonify_ameba_write_arg_ameba_to_file(FILE *out, struct arg_ameba *val)
{
    if (!out)
        return;

    int dst_len = 512;
    char dst[dst_len];

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    jsonify_ameba_write_arg_ameba(&s, val);

    jsonify_core_close_obj(&s);

    fprintf(out, "%s\n", &dst[0]);
}