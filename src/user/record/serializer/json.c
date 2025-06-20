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

#include <stddef.h>
#include "user/error.h"
#include "user/record/serializer/serializer.h"
#include "user/jsonify/record.h"


static long record_serializer_json_serialize(void *dst, size_t dst_len, struct elem_common *record, size_t record_len)
{
    int err = record_serializer_common(dst, dst_len, record, record_len);
    if (err != 0)
        return err;

    int write_interpreted = 0;

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    int jsonify_result = jsonify_record(&s, record, record_len, write_interpreted);

    jsonify_core_close_obj(&s);

    jsonify_core_write_newline(&s);

    if (jsonify_result < 0)
    {
        return jsonify_result;
    }

    if (jsonify_core_has_overflown(&s))
    {
        return ERR_DST_INSUFFICIENT;
    }

    return jsonify_core_get_total_chars_written(&s);
}


const struct record_serializer record_serializer_json = {
    .serialize = record_serializer_json_serialize
};