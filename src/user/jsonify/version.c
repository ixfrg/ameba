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

#include "user/jsonify/version.h"
#include "common/version.h"


int jsonify_version_write_app_version(struct json_buffer *s)
{
    int total = 0;
    total += jsonify_types_write_version(s, "app_version", &app_version);
    return total;
}

int jsonify_version_write_record_version(struct json_buffer *s)
{
    int total = 0;
    total += jsonify_types_write_version(s, "record_version", &record_version);
    return total;
}

int jsonify_version_write_all_versions(struct json_buffer *s)
{
    int total = 0;
    total += jsonify_version_write_app_version(s);
    total += jsonify_version_write_record_version(s);
    return total;
}

void jsonify_version_write_all_versions_to_file(FILE *out)
{
    if (!out)
        return;

    int dst_len = 512;
    char dst[dst_len];

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    jsonify_version_write_all_versions(&s);

    jsonify_core_close_obj(&s);

    fprintf(out, "%s\n", &dst[0]);
}