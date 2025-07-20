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

    A module to help write versions to json_buffer.

    See 'core.h'.

*/

#include "user/jsonify/types.h"


/*
    Write app version to json_buffer.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_version_write_app_version(struct json_buffer *s);

/*
    Write record version to json_buffer.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_version_write_record_version(struct json_buffer *s);

/*
    Write all versions to json_buffer.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_version_write_all_versions(struct json_buffer *s);

/*
    Write all versions to give output file.

    Return:
        See 'jsonify_core_snprintf'.
*/
void jsonify_version_write_all_versions_to_file(FILE *out);