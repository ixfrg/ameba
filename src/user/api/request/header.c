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

#include "common/version.h"
#include "user/helper/log.h"
#include "user/api/common.h"
#include "user/api/request/header.h"


int api_request_header_init(struct api_request_header *header, api_request_type_t req_type)
{
    if (!header)
    {
        log_state_msg(
            APP_STATE_OPERATIONAL_WITH_ERROR,
            "Failed api_request_header_init. NULL argument(s)"
        );
        return -1;
    }
    if (api_header_init(&header->header) != 0)
    {
        return -1;
    }
    header->request_type = req_type;
    return 0;
}