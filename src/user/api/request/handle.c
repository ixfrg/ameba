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

#include <stdatomic.h>

#include "user/helper/log.h"
#include "user/jsonify/version.h"
#include "user/api/request/handle.h"
#include "user/api/response/error/create.h"
#include "user/api/request/get_control/handle.h"


static struct api_request_handler* request_handlers[] = {
    [API_REQUEST_TYPE_GET_CONTROL] = &api_request_handler_get_control
};
static int request_handlers_len = sizeof(request_handlers) / sizeof(struct api_request_handler*);


int api_request_handle(struct api_context *api_ctx, struct api_request_header *request, size_t request_size, void **response)
{
    if (!api_ctx || !request || !response)
    {
        log_state_msg(APP_STATE_OPERATIONAL_WITH_ERROR, "Failed api_request_handle. NULL argument(s)");
        return api_response_error_create_alloc_init(response, API_RESPONSE_ERROR_INVALID_DATA);
    }

    api_request_type_t request_type = request->request_type;

    if (request_type < 0 || request_type >= request_handlers_len)
    {
        log_state_msg(APP_STATE_OPERATIONAL_WITH_ERROR, "Failed api_request_handle. Invalid request type '%u'", request_type);
        return api_response_error_create_alloc_init(response, API_RESPONSE_ERROR_INVALID_MSG_TYPE);
    }

    struct api_request_handler* request_handler = request_handlers[request_type];

    if (!request_handler)
    {
        log_state_msg(
            APP_STATE_OPERATIONAL_WITH_ERROR,
            "Failed api_request_handle. No handler for request type '%u'",
            request_type
        );
        return api_response_error_create_alloc_init(response, API_RESPONSE_ERROR_INVALID_MSG_TYPE);
    }

    int handle_result = request_handler->handle(api_ctx, request, request_size, response);
    if (handle_result != 0)
    {
        log_state_msg(
            APP_STATE_OPERATIONAL_WITH_ERROR,
            "Failed api_request_handle. Failed to handle request type '%u'",
            request_type
        );
        return api_response_error_create_alloc_init(response, API_RESPONSE_ERROR_INTERNAL_ERROR);
    }

    return 0;
}
