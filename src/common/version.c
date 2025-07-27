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

#include "common/config.h"


static const struct elem_version app_version = {
    .major = PACKAGE_VERSION_MAJOR,
    .minor = PACKAGE_VERSION_MINOR,
    .patch = PACKAGE_VERSION_PATCH
};

static const struct elem_version record_version = {
    .major = RECORD_VERSION_MAJOR,
    .minor = RECORD_VERSION_MINOR,
    .patch = RECORD_VERSION_PATCH
};

static const struct elem_version api_version = {
    .major = API_VERSION_MAJOR,
    .minor = API_VERSION_MINOR,
    .patch = API_VERSION_PATCH
};


int version_get_app_version(struct elem_version *dst)
{
    if (!dst)
        return -1;
    *dst = app_version;
    return 0;
}

int version_get_record_version(struct elem_version *dst)
{
    if (!dst)
        return -1;
    *dst = record_version;
    return 0;
}

int version_get_api_version(struct elem_version *dst)
{
    if (!dst)
        return -1;
    *dst = api_version;
    return 0;
}