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

#include "user/helper/log.h"
#include "user/api/response/error/types.h"
#include "user/api/response/error/create.h"
#include "user/api/request/get_control/handle.h"
#include "user/api/response/get_control/create.h"


static const char *api_request_get_control_handle_get_name()
{
    return "get_control_request_handler";
}

static int api_request_get_control_handle(struct api_context *api_ctx, struct api_request_header *request, size_t request_size, void **response)
{
    if (!api_ctx || !request || !response)
    {
        log_state_msg(APP_STATE_OPERATIONAL_WITH_ERROR, "Failed api_request_get_control_handle. NULL argument(s)");
        return api_response_error_create_alloc_init(response, API_RESPONSE_ERROR_INVALID_DATA);
    }

    if (request_size < sizeof(struct api_request_get_control))
    {
        log_state_msg(
            APP_STATE_OPERATIONAL_WITH_ERROR,
            "Failed api_request_get_control_handle. Invalid request size"
        );
        return api_response_error_create_alloc_init(response, API_RESPONSE_ERROR_INVALID_DATA);
    }
    // unused
    // struct api_request_get_control *get_control_request = request;

    struct control control;
    if (api_ctx->get_control_from_bpf_map != NULL && api_ctx->get_control_from_bpf_map(&control) != 0)
    {
        log_state_msg(
            APP_STATE_OPERATIONAL_WITH_ERROR,
            "Failed api_request_get_control_handle. Failed to get control."
        );
        return api_response_error_create_alloc_init(response, API_RESPONSE_ERROR_INVALID_DATA);
    }
    if (api_response_get_control_create_alloc_init(response, &control) != 0)
    {
        log_state_msg(
            APP_STATE_OPERATIONAL_WITH_ERROR,
            "Failed api_request_get_control_handle. Failed to create get_control response."
        );
        return api_response_error_create_alloc_init(response, API_RESPONSE_ERROR_INVALID_DATA);
    }
    return 0;
}

struct api_request_handler api_request_handler_get_control = {
    .get_name = &api_request_get_control_handle_get_name,
    .handle = &api_request_get_control_handle
};