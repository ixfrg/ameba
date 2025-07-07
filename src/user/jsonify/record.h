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

    A module to help write record types to json_buffer.

    See 'core.h'.

*/

#include "user/jsonify/types.h"

/*
    Write record to json_buffer.
    
    e_common contains the record type. It is cast to record_* based on it's type to get the actual record.

    Set 'write_interpreted' to non-zero value to interpret the record's contents like socket address.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_record(struct json_buffer *s, struct elem_common *e_common, int data_len, int write_interpreted);