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
#include <string.h>
#include "user/include/error.h"
#include "user/record/serializer/binary.h"


static long record_serializer_binary_serialize(void *dst, size_t dst_len, struct elem_common *record, size_t record_len)
{
    int err = record_serializer_common(dst, dst_len, record, record_len);
    if (err != 0)
        return err;

    /*
        Required size:
            First 'sizeof(size_t)' bytes contain the size of the data.
            The remaining bytes are the data itself.
    */
    size_t required_size = sizeof(size_t) + record_len;
    if (required_size > dst_len)
        return ERR_DST_INSUFFICIENT;

    unsigned char *dst_c = (unsigned char *)dst;
    long i = 0;

    memcpy(&dst_c[i], &record_len, sizeof(size_t));
    i += sizeof(size_t);
    memcpy(&dst_c[i], record, record_len);
    i += record_len;

    return i;
}


const struct record_serializer record_serializer_binary = {
    .serialize = record_serializer_binary_serialize
};