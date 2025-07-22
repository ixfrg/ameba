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

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include <bpf/bpf.h>

#include "common/constants.h"
#include "common/types.h"
#include "common/version.h"
#include "user/helpers/prog_op.h"
#include "user/helpers/log.h"


int prog_op_create_lock_dir(void)
{
    if (mkdir(DIR_PATH_FOR_AMEBA_OP_LOCK, 0700) != 0)
    {
        if (errno == EEXIST)
        {
            log_state_msg(
                APP_STATE_STOPPED_WITH_ERROR,
                "An existing ameba operation is already in process. If you think this is incorrect, manually remove the dir '%s'",
                DIR_PATH_FOR_AMEBA_OP_LOCK
            );
        } else {
            log_state_msg(
                APP_STATE_STOPPED_WITH_ERROR,
                "Failed to create ameba operation lock dir '%s'. Err: %s",
                DIR_PATH_FOR_AMEBA_OP_LOCK, strerror(errno)
            );
        }
        return -1;
    }
    return 0;
}

int prog_op_remove_lock_dir(void)
{
    if (rmdir(DIR_PATH_FOR_AMEBA_OP_LOCK) != 0) {
        if (errno == ENOENT)
        {
            // Doesn't exist
            return 0;
        }
        log_state_msg(
            APP_STATE_STOPPED_WITH_ERROR,
            "Failed to remove ameba operation lock dir '%s'. Err: %s",
            DIR_PATH_FOR_AMEBA_OP_LOCK, strerror(errno)
        );
        return -1;
    }
    return 0;
}

static int compare_elem_versions(struct elem_version *expected, struct elem_version *actual)
{
    if (!expected || !actual)
        return -1;
    if (
        expected->major == actual->major
        && expected->minor == actual->minor
        && expected->patch == actual->patch
    )
    {
        return 0;
    }
    log_state_msg(
        APP_STATE_STOPPED_WITH_ERROR,
        "Version mismatch. Expected: %d.%d.%d, Actual: %d.%d.%d",
        expected->major, expected->minor, expected->patch,
        actual->major, actual->minor, actual->patch
    );
    return -1;
}

static int get_elem_version_in_map(char *version_map_path, const struct elem_version *dst)
{
    if (!version_map_path || !dst)
        return -1;
    int map_fd = bpf_obj_get(version_map_path);
    if (map_fd < 0) {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to open bpf map '%s'. Err: %d", version_map_path, map_fd);
        return -1;
    }
    int key = 0;
    int err = bpf_map_lookup_elem(map_fd, &key, dst);
    if (err < 0) {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "No key '%d' in map '%s'. Err: %s", key, version_map_path, err);
        return -1;
    }
    return 0;
}

static int compare_ameba_version_in_map(char *version_map_path, struct elem_version *expected_version)
{
    if (!version_map_path || !expected_version)
    {
        return -1;
    }
    struct elem_version actual_version;
    if (get_elem_version_in_map(version_map_path, &actual_version) != 0)
    {
        return -1;
    }
    return compare_elem_versions(expected_version, &actual_version);
}

static int compare_ameba_app_version_in_map()
{
    int buf_size = 256;
    char version_map_path[buf_size];

    int ret;

    ret = snprintf(
        &version_map_path[0], buf_size, "%s/%s",
        DIR_PATH_FOR_PINNING_AMEBA_BPF,
        AMEBA_MAP_NAME_APP_VERSION_STR
    );
    if (ret >= buf_size)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to create path for version map '%s'", AMEBA_MAP_NAME_APP_VERSION_STR);
        return -1;
    }
    return compare_ameba_version_in_map(&version_map_path[0], &app_version);
}

static int compare_ameba_record_version_in_map()
{
    int buf_size = 256;
    char version_map_path[buf_size];

    int ret;

    ret = snprintf(
        &version_map_path[0], buf_size, "%s/%s",
        DIR_PATH_FOR_PINNING_AMEBA_BPF,
        AMEBA_MAP_NAME_RECORD_VERSION_STR
    );
    if (ret >= buf_size)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to create path for version map '%s'", AMEBA_MAP_NAME_RECORD_VERSION_STR);
        return -1;
    }
    return compare_ameba_version_in_map(&version_map_path[0], &record_version);
}

int prog_op_compare_versions_in_loaded_maps_with_current_versions()
{
    int ret = 0;

    ret = compare_ameba_app_version_in_map();

    if (ret != 0)
        return ret;

    ret = compare_ameba_record_version_in_map();

    if (ret != 0)
        return ret;

    return ret;
}

int prog_op_ameba_must_be_pinned(void)
{
    struct stat st;
    if (stat(DIR_PATH_FOR_PINNING_AMEBA_BPF, &st) == 0)
    {
        if (S_ISDIR(st.st_mode))
        {
            return 0;
        } else
        {
            log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Ameba pin dir '%s' is not a directory", DIR_PATH_FOR_PINNING_AMEBA_BPF);
            return -1;
        }
    } else
    {
        if (errno == ENOENT)
        {
            log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Ameba pin dir '%s' does not exist", DIR_PATH_FOR_PINNING_AMEBA_BPF);
            return -1;
        } else
        {
            log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to check for ameba pin dir '%s'. Err: %s", DIR_PATH_FOR_PINNING_AMEBA_BPF, strerror(errno));
            return -1;
        }
    }
}