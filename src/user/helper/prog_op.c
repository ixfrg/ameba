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
#include <dirent.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <bpf/bpf.h>

#include "common/constants.h"
#include "common/types.h"
#include "common/version.h"
#include "user/helper/prog_op.h"
#include "user/helper/log.h"

#include "ameba.skel.h"


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

static int compare_elem_versions(const struct elem_version *expected, const struct elem_version *actual)
{
    int result = version_check_equal((struct elem_version *)expected, (struct elem_version *)actual);
    if (result == -1)
    {
        return -1;
    }
    if (result == 1)
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
    int err = bpf_map_lookup_elem(map_fd, &key, (void*)dst);
    if (err < 0) {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "No key '%d' in map '%s'. Err: %s", key, version_map_path, err);
        return -1;
    }
    return 0;
}

static int compare_ameba_version_in_map(char *version_map_path, const struct elem_version *expected_version)
{
    if (!version_map_path || !expected_version)
    {
        return -1;
    }
    const struct elem_version actual_version;
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
    struct elem_version app_version;
    if (version_get_app_version(&app_version) != 0)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to get local app version");
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
    struct elem_version record_version;
    if (version_get_record_version(&record_version) != 0)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to get local record version");
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

int prog_op_ameba_must_not_be_pinned(void)
{
    struct stat st;
    if (stat(DIR_PATH_FOR_PINNING_AMEBA_BPF, &st) == 0)
    {
        if (S_ISDIR(st.st_mode))
        {
            log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Ameba pin dir '%s' exists", DIR_PATH_FOR_PINNING_AMEBA_BPF);
            return -1;
        } else
        {
            log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Ameba pin dir '%s' is not a directory", DIR_PATH_FOR_PINNING_AMEBA_BPF);
            return -1;
        }
    } else
    {
        if (errno == ENOENT)
        {
            return 0;
        } else
        {
            log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to check for ameba pin dir '%s'. Err: %s", DIR_PATH_FOR_PINNING_AMEBA_BPF, strerror(errno));
            return -1;
        }
    }
}

static int get_control_map_path(char *path_buf, int path_buf_size)
{
    int ret = 0;
    ret = snprintf(
        path_buf, path_buf_size, "%s/%s",
        DIR_PATH_FOR_PINNING_AMEBA_BPF,
        AMEBA_MAP_NAME_CONTROL_STR
    );
    if (ret >= path_buf_size)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to create path for control input map '%s'", AMEBA_MAP_NAME_CONTROL_STR);
        return -1;
    }
    return 0;
}

static int get_control_map_fd()
{
    int map_path_buf_size = 256;
    char map_path_buf[map_path_buf_size];

    int ret = 0;

    ret = get_control_map_path(&map_path_buf[0], map_path_buf_size);

    if (ret != 0)
        return -1;

    int map_fd = bpf_obj_get(&map_path_buf[0]);
    if (map_fd < 0)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to open bpf map '%s'. Err: %d", &map_path_buf[0], map_fd);
        return -1;
    }
    return map_fd;
}

int prog_op_set_control_in_map(struct control *input)
{
    if (!input)
        return -1;

    int ret = 0;

    int map_fd = get_control_map_fd();
    if (map_fd < 0)
    {
        return -1;
    }
    int key = 0;
    ret = bpf_map_update_elem(map_fd, &key, input, BPF_ANY);
    if (ret < 0)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to set control input in map");
        return -1;
    }
    return ret;
}

int prog_op_get_control_in_map(struct control *input)
{
    if (!input)
        return -1;

    int ret = 0;

    int map_fd = get_control_map_fd();
    if (map_fd < 0)
    {
        return -1;
    }
    int key = 0;
    ret = bpf_map_lookup_elem(map_fd, &key, input);
    if (ret != 0)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to get control input in map");
        return -1;
    }
    return ret;
}

static int get_output_ringbuf_path(char *path_buf, int path_buf_size)
{
    int ret = 0;
    ret = snprintf(
        path_buf, path_buf_size, "%s/%s",
        DIR_PATH_FOR_PINNING_AMEBA_BPF,
        AMEBA_MAP_NAME_OUTPUT_RINGBUF_STR
    );
    if (ret >= path_buf_size)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to create path for output ringbuf '%s'", AMEBA_MAP_NAME_OUTPUT_RINGBUF_STR);
        return -1;
    }
    return 0;
}

int prog_op_get_output_ringbuf_fd()
{
    int path_buf_size = 256;
    char path_buf[path_buf_size];

    int ret = 0;

    ret = get_output_ringbuf_path(&path_buf[0], path_buf_size);

    if (ret != 0)
        return -1;

    int fd = bpf_obj_get(&path_buf[0]);
    if (fd < 0)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to open bpf ringbuf '%s'. Err: %d", &path_buf[0], fd);
        return -1;
    }
    return fd;
}

static int unpin_progs_and_maps()
{
    int result = 0;

    DIR *dir = NULL;
    dir = opendir(DIR_PATH_FOR_PINNING_AMEBA_BPF);
    if (!dir)
    {
        if (errno == ENOENT)
            log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Ameba is not pinned. Err: %s", strerror(errno));
        else
            log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to open ameba pin dir '%s'. Err: %s", DIR_PATH_FOR_PINNING_AMEBA_BPF, strerror(errno));
        result = -1;
        goto exit;
    }

    while (1)
    {
        errno = 0;
        struct dirent *dir_entry = readdir(dir);
        if (dir_entry == NULL)
        {
            if (errno != 0)
            {
                log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to read ameba pin dir '%s'. Err: %s", DIR_PATH_FOR_PINNING_AMEBA_BPF, strerror(errno));
                result = -1;
                goto close_and_rm_dir;
            }
            break;
        }

        if (strcmp(dir_entry->d_name, ".") == 0 || strcmp(dir_entry->d_name, "..") == 0)
            continue;

        char file_path[PATH_MAX];
        snprintf(file_path, sizeof(file_path), "%s/%s", DIR_PATH_FOR_PINNING_AMEBA_BPF, dir_entry->d_name);

        if (unlink(file_path) != 0)
        {
            log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to delete pinned bpf obj '%s'. Err: %s", &file_path[0], strerror(errno));
        }
    }

close_and_rm_dir:
    closedir(dir);
    if (rmdir(DIR_PATH_FOR_PINNING_AMEBA_BPF) != 0)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to delete ameba pin dir '%s'. Err: %s", DIR_PATH_FOR_PINNING_AMEBA_BPF, strerror(errno));
        result = -1;
    }

exit:
    return result;
}

static int pin_progs_and_maps(struct ameba *skel)
{
    int err = 0;

    if (mkdir(DIR_PATH_FOR_PINNING_AMEBA_BPF, 0700) && errno != EEXIST)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to create dir (%s) for bpf pinning. Err: %d", DIR_PATH_FOR_PINNING_AMEBA_BPF, errno);
        err = -1;
        goto exit;
    }

    if ((err = bpf_object__pin(skel->obj, DIR_PATH_FOR_PINNING_AMEBA_BPF)) != 0)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to pin. Err: %d", err);
        err = -1;
        goto rm_pin_dir;
    }

    goto exit;

rm_pin_dir:
    if (rmdir(DIR_PATH_FOR_PINNING_AMEBA_BPF) != 0)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to rm pin dir. Err: %d", errno);
    }

exit:
    return err;
}

static int attach_progs(struct ameba *skel)
{
    int err = ameba__attach(skel);
    if (err != 0)
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Error attaching skeleton");
    return err;
}

static int set_control_in_map(struct ameba *skel, struct control *control)
{
    if (!skel || !control)
        return -1;

    int update_flags = BPF_ANY;

    int key = 0;
    int ret = bpf_map__update_elem(
        skel->maps.AMEBA_MAP_NAME_CONTROL,
        &key, sizeof(key),
        control, sizeof(struct control),
        update_flags
    );
    if (ret != 0)
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to set control input in map");
    return ret;
}

static int set_bpf_app_version_in_map(struct ameba *skel, const struct elem_version *version)
{
    if (!skel || !version)
        return -1;

    int version_key = 0;
    int ret = bpf_map__update_elem(
        skel->maps.AMEBA_MAP_NAME_APP_VERSION,
        &version_key, sizeof(int),
        version, sizeof(struct elem_version),
        BPF_ANY
    );
    if (ret != 0)
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to set app version in map");
    return ret;
}

static int set_bpf_record_version_in_map(struct ameba *skel, const struct elem_version *version)
{
    if (!skel || !version)
        return -1;

    int version_key = 0;
    int ret = bpf_map__update_elem(
        skel->maps.AMEBA_MAP_NAME_RECORD_VERSION,
        &version_key, sizeof(int),
        version, sizeof(struct elem_version),
        BPF_ANY
    );
    if (ret != 0)
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to set record version in map");
    return ret;
}

static int set_bpf_version_maps_with_current_versions(struct ameba *skel)
{
    int ret = 0;

    struct elem_version app_version;
    if (version_get_app_version(&app_version) != 0)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to get local app version");
        return -1;
    }
    ret = set_bpf_app_version_in_map(skel, &app_version);

    if (ret != 0)
        return ret;

    struct elem_version record_version;
    if (version_get_record_version(&record_version) != 0)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to get local record version");
        return -1;
    }
    ret = set_bpf_record_version_in_map(skel, &record_version);

    return ret;
}

static struct ameba *open_and_load_skel()
{
    struct ameba *skel = NULL;
    skel = ameba__open_and_load();
    if (!skel)
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to load bpf skeleton");
    return skel;
}

int prog_op_pin_bpf_progs_and_maps(struct arg_pin *arg, struct control *control)
{
    if (!arg || !control)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed prog_op_pin_bpf_progs_and_maps. NULL argument(s)");
        return -1;
    }

    struct ameba *skel = NULL;
    int result = 0;

    result = prog_op_ameba_must_not_be_pinned();
    if (result != 0)
    {
        result = -1;
        goto exit;
    }

    skel = open_and_load_skel();
    if (!skel)
    {
        result = -1;
        goto exit;
    }

    if (set_bpf_version_maps_with_current_versions(skel) != 0)
    {
        result = -1;
        goto exit;
    }

    if (set_control_in_map(skel, control) != 0)
    {
        result = -1;
        goto exit;
    }

    if (attach_progs(skel) != 0)
    {
        result = -1;
        goto exit;
    }

    if (pin_progs_and_maps(skel) != 0)
    {
        result = -1;
        goto exit;
    }

exit:
    return result;
}

int prog_op_unpin_bpf_progs_and_maps(struct arg_unpin *arg)
{
    if (!arg)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed prog_op_unpin_bpf_progs_and_maps. NULL argument(s)");
        return -1;
    }

    int result = 0;

    result = prog_op_ameba_must_be_pinned();
    if (result != 0)
    {
        result = -1;
        goto exit;
    }

    if (prog_op_compare_versions_in_loaded_maps_with_current_versions() != 0)
    {
        result = -1;
        goto exit;
    }

    if (unpin_progs_and_maps() != 0)
    {
        result = -1;
        goto exit;
    }

exit:
    return result;
}

struct ring_buffer * prog_op_setup_output_ringbuf_reader(int (*handle_ringbuf_data)(void *ctx, void *data, size_t data_len))
{
    int ringbuf_fd = prog_op_get_output_ringbuf_fd();
    if (ringbuf_fd < 0)
    {
        return NULL;
    }

    struct ring_buffer *ringbuf = ring_buffer__new(ringbuf_fd, handle_ringbuf_data, NULL, NULL);

    if (!ringbuf)
    {
        log_state_msg(
            APP_STATE_STOPPED_WITH_ERROR,
            "Failed to create output ringbuf instance"
        );
        return NULL;
    }

    return ringbuf;
}