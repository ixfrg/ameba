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
#include "user/helper/lock.h"
#include "user/helper/prog_op.h"
#include "user/api/context.h"
#include "user/api/types.h"
#include "user/api/request/handle.h"
#include "user/api/response/error/create.h"


static struct lock global_lock = {0};
static struct api_context global_api_context = {
    .bpf_must_be_pinned = &prog_op_ameba_must_be_pinned,
    .get_control_from_bpf_map = &prog_op_get_control_in_map
};


static void log_incorrect_version_msg(struct elem_version *msg_version)
{
    int err_buf_size = 512;
    char err_buf[err_buf_size];
    struct json_buffer err_json;
    jsonify_core_init(&err_json, &err_buf[0], err_buf_size);
    jsonify_core_open_obj(&err_json);
    struct elem_version api_version;
    version_get_api_version(&api_version);
    jsonify_version_write_api_version(&err_json);
    jsonify_types_write_version(&err_json, "expected", &api_version);
    jsonify_types_write_version(&err_json, "actual", msg_version);
    jsonify_core_close_obj(&err_json);
    
    log_state_msg_and_child_js(
        APP_STATE_OPERATIONAL_WITH_ERROR,
        "Failed internal_unsafe_api_handle. Incorrect version.",
        "api_versions", &err_json
    );
}

static int internal_unsafe_api_handle(void *request, size_t request_size, void **response, uint32_t *response_size)
{
    if (!request || !response || !response_size)
    {
        log_state_msg(APP_STATE_OPERATIONAL_WITH_ERROR, "Failed internal_unsafe_api_handle. NULL argument(s)");
        return api_response_error_create_alloc_init(response, response_size, API_RESPONSE_ERROR_INVALID_DATA);
    }

    if (request_size < sizeof(struct api_header))
    {
        log_state_msg(
            APP_STATE_OPERATIONAL_WITH_ERROR,
            "Failed internal_unsafe_api_handle. Invalid request size"
        );
        return api_response_error_create_alloc_init(response, response_size, API_RESPONSE_ERROR_INVALID_DATA);
    }

    struct api_header *header = request;

    if (header->magic != AMEBA_MAGIC)
    {
        log_state_msg(
            APP_STATE_OPERATIONAL_WITH_ERROR,
            "Failed internal_unsafe_api_handle. Invalid magic"
        );
        return api_response_error_create_alloc_init(response, response_size, API_RESPONSE_ERROR_INVALID_DATA);
    }

    int version_check_result = version_check_equal_api_version(&header->version);
    if (version_check_result != 1)
    {
        log_incorrect_version_msg(&header->version);
        return api_response_error_create_alloc_init(response, response_size, API_RESPONSE_ERROR_INVALID_VERSION);
    }

    return api_request_handle(&global_api_context, request, request_size, response, response_size);
}

int api_handle(void *request, uint32_t request_size, void **response, uint32_t *response_size)
{
    if (lock_acquire(&global_lock) != 0)
    {
        return api_response_error_create_alloc_init(response, response_size, API_RESPONSE_ERROR_INTERNAL_ERROR);
    }

    int ret = internal_unsafe_api_handle(request, request_size, response, response_size);

    lock_release(&global_lock);

    return ret;
}