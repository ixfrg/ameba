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
#include "user/helper/log.h"
#include "user/api/response/header.h"
#include "user/api/response/error/create.h"


int api_response_error_create_alloc_init(void **resp_ptr, api_response_error_t err)
{
    struct api_response_error *ptr = malloc(sizeof(struct api_response_error));
    if (!ptr)
    {
        return -1;
    }
    if (api_response_error_create_init(ptr, err) != 0)
    {
        free(ptr);
        return -1;
    }
    *resp_ptr = ptr;
    return 0;
}

int api_response_error_create_init(struct api_response_error *resp, api_response_error_t err)
{
    if (!resp)
    {
        log_state_msg(
            APP_STATE_OPERATIONAL_WITH_ERROR,
            "Failed api_response_error_create_init. NULL argument(s)"
        );
        return -1;
    }
    if (api_response_header_init(&resp->header, API_RESPONSE_TYPE_ERROR) != 0)
    {
        return -1;
    }
    resp->error = err;
    return 0;
}