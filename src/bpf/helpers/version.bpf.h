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

#include "common/vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common/constants.h"

#include "common/types.h"


/*
    Update the version for record in version map with the value of 'src'

    Returns:
        0    => Success
        -ive => Error
*/
long version_record_version_map_update(struct elem_version *src);

/*
    Lookup the version for record in version map and populate 'dst'

    Returns:
        0    => Success
        -ive => Error
*/
long version_record_version_map_lookup(struct elem_version *dst);

/*
    Update the version for app in version map with the value of 'src'

    Returns:
        0    => Success
        -ive => Error
*/
long version_app_version_map_update(struct elem_version *src);

/*
    Lookup the version for app in version map and populate 'dst'

    Returns:
        0    => Success
        -ive => Error
*/
long version_app_version_map_lookup(struct elem_version *dst);
