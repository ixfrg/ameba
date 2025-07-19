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

#include "bpf/helpers/version.bpf.h"


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct elem_version);
    __uint(max_entries, 1);
} AMEBA_MAP_NAME_APP_VERSION SEC(".maps");
static void *app_version_map = &AMEBA_MAP_NAME_APP_VERSION;


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct elem_version);
    __uint(max_entries, 1);
} AMEBA_MAP_NAME_RECORD_VERSION SEC(".maps");
static void *record_version_map = &AMEBA_MAP_NAME_RECORD_VERSION;


static int get_key_for_record_version(void)
{
    return 0;
}

static int get_key_for_app_version(void)
{
    return 0;
}

long version_record_version_map_update(struct elem_version *src)
{
    if (!src)
        return -1;
    int key = get_key_for_record_version();
    return bpf_map_update_elem(record_version_map, &key, src, BPF_ANY);
}

long version_record_version_map_lookup(struct elem_version *dst)
{
    if (!dst)
        return -1;
    int key = get_key_for_record_version();
    struct elem_version *val = bpf_map_lookup_elem(record_version_map, &key);
    if (!val)
        return -1;
    *dst = *val;
    return 0;
}

long version_app_version_map_update(struct elem_version *src)
{
    if (!src)
        return -1;
    int key = get_key_for_app_version();
    return bpf_map_update_elem(app_version_map, &key, src, BPF_ANY);
}

long version_app_version_map_lookup(struct elem_version *dst)
{
    if (!dst)
        return -1;
    int key = get_key_for_app_version();
    struct elem_version *val = bpf_map_lookup_elem(app_version_map, &key);
    if (!val)
        return -1;
    *dst = *val;
    return 0;
}
