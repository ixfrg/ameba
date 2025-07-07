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

    A module to define the interface for record serialization.

*/

#include <sys/types.h>

#include "common/types.h"


/*
    A function to perform some common record serialization checks.

    1. Check if pointers are null
    2. Check if lengths are positive
    3. Check if header (i.e. elem_common) is present
    4. Check if magic value in header is correct

    It does no serialization!

    Return:
        -ive -> The error
        0    -> No error
        +ive -> Undefined
*/
long record_serializer_common(void *dst, size_t dst_len, struct elem_common *record, size_t record_len);


struct record_serializer {

    /*
        Serialize a record to a different format.
        Put the serialized record into 'dst'.

        Return:
            +ive -> The actual size of 'dst'
            -ive -> Error
            0    -> Undefined

    */
    long (*serialize)(void *dst, size_t dst_len, struct elem_common *record, size_t record_len);

};