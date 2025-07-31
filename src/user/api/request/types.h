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
    A module to define api requests.
*/

#include "user/api/types.h"
#include "user/api/context.h"


typedef enum
{
    API_REQUEST_TYPE_GET_CONTROL = 1
} api_request_type_t;


struct api_request_header
{
    struct api_header header;
    api_request_type_t request_type;
};

struct api_request_handler
{
    /*
        Get a pointer to a user friendly name for the handler.
    */
    const char * (*get_name)();

    /*
        Handle the request, and create an appropriate response.

        Returns:
            0  => Success i.e. response is properly formed.
            -1 => Failed

        NOTE:
            response is malloc'ed and must be free'ed by the caller after use.
    */
    int (*handle)(struct api_context *api_ctx, struct api_request_header *request, size_t request_size, void **response);
};