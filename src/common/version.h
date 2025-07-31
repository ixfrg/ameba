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

    A module for defining versions.

*/

#include <unistd.h>

#include "common/types.h"


/*
    Populate dst with the current app version.

    Returns:
        0  => Success
        -1 => Invalid dst
*/
int version_get_app_version(struct elem_version *dst);

/*
    Populate dst with the current record version.

    Returns:
        0  => Success
        -1 => Invalid dst
*/
int version_get_record_version(struct elem_version *dst);

/*
    Populate dst with the current api version.

    Returns:
        0  => Success
        -1 => Invalid dst
*/
int version_get_api_version(struct elem_version *dst);

/*
    Check if elems are equal.

    Returns:
        1  => Equal
        0  => Not equal 
        -1 => Error
*/
int version_check_equal(struct elem_version *expected, struct elem_version *actual);

/*
    Check if actual api version is equal to the current one.

    Returns:
        1  => Equal
        0  => Not equal 
        -1 => Error
*/
int version_check_equal_api_version(struct elem_version *actual);
