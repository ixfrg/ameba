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

#include "user/helper/log.h"
#include "user/api/response/error/types.h"


/*
    Allocate and initialize response error.

    Returns:
        0   => Success
        -1  => Error

    NOTE:
        resp_ptr is alloc'ed on success and must be free'ed after use.
*/
int api_response_error_create_alloc_init(void **resp_ptr, api_response_error_t err);

/*
    Initialize response error.

    Returns:
        0   => Success
        -1  => Error
*/
int api_response_error_create_init(struct api_response_error *resp, api_response_error_t err);