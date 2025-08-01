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
#include <sys/types.h>

#include "user/include/error.h"
#include "common/types.h"
#include "user/record/serializer/serializer.h"


long record_serializer_common(void *dst, size_t dst_len, struct elem_common *record, size_t record_len)
{
    if (dst == NULL)
        return ERR_DST_INVALID;
    if (dst_len <= 0)
        return ERR_DST_INSUFFICIENT;
    if (record == NULL)
        return ERR_RECORD_INVALID;
    if (record_len <= 0)
        return ERR_RECORD_INVALID;

    if (record_len < sizeof(struct elem_common))
        return ERR_RECORD_INVALID_HEADER;

    if (record->magic != AMEBA_MAGIC)
        return ERR_RECORD_INVALID_MAGIC;

    return 0;
}