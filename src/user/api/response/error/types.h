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
    A module to define api response for error.
*/

#include "user/api/response/types.h"


typedef enum {
    API_RESPONSE_ERROR_INVALID_DATA = 1,
    API_RESPONSE_ERROR_INVALID_VERSION,
    API_RESPONSE_ERROR_INVALID_MSG_TYPE,
    API_RESPONSE_ERROR_INTERNAL_ERROR
} api_response_error_t;


struct api_response_error
{
    struct api_response_header header;
    api_response_error_t error;
};




