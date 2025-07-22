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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>

#include "common/types.h"
#include "common/version.h"
#include "common/constants.h"
#include "user/helpers/prog_op.h"
#include "user/helpers/log.h"
#include "user/args/unpin.h"


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

static void parse_user_input(int argc, char *argv[])
{
    struct unpin_input_arg input_arg;
    user_args_unpin_parse(&input_arg, argc, argv);

    struct arg_parse_state *a_p_s = &(input_arg.parse_state);
    if (user_args_helper_state_is_exit_set(a_p_s))
    {
        exit(user_args_helper_state_get_code(a_p_s));
    }
}

int main(int argc, char *argv[])
{
    int result = 0;

    parse_user_input(argc, argv);

    if (prog_op_create_lock_dir() != 0)
    {
        result = -1;
        goto exit;
    }

    result = prog_op_ameba_must_be_pinned();
    if (result != 0)
    {
        result = -1;
        goto rm_prog_op_lock_dir;
    }

    if (prog_op_compare_versions_in_loaded_maps_with_current_versions() != 0)
    {
        result = -1;
        goto rm_prog_op_lock_dir;
    }

    if (unpin_progs_and_maps() != 0)
    {
        result = -1;
        goto rm_prog_op_lock_dir;
    }

    log_state_msg_with_current_pid(APP_STATE_OPERATIONAL_PID, "Unpinned");

rm_prog_op_lock_dir:
    prog_op_remove_lock_dir();

exit:
    return result;
}
