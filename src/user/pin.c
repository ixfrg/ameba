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

#include "common/types.h"
#include "common/version.h"
#include "user/helpers/log.h"
#include "user/helpers/prog_op.h"
#include "user/args/pin.h"

#include "ameba.skel.h"


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

static int set_default_control_input_map(struct ameba *skel)
{
    if (!skel)
        return -1;

    struct control_input control_input;
    control_set_default(&control_input);

    int update_flags = BPF_ANY;

    int key = 0;
    int ret = bpf_map__update_elem(
        skel->maps.AMEBA_MAP_NAME_CONTROL_INPUT,
        &key, sizeof(key),
        &control_input, sizeof(struct control_input),
        update_flags
    );
    if (ret != 0)
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to set default control input in map");
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
        &version, sizeof(struct elem_version),
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
        &version, sizeof(struct elem_version),
        BPF_ANY
    );
    if (ret != 0)
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to set record version in map");
    return ret;
}

static int set_bpf_version_maps_with_current_versions(struct ameba *skel)
{
    int ret = 0;

    ret = set_bpf_app_version_in_map(skel, &app_version);

    if (ret != 0)
        return ret;

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

static int attach_progs(struct ameba *skel)
{
    int err = ameba__attach(skel);
    if (err != 0)
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Error attaching skeleton");
    return err;
}

static void parse_user_input(int argc, char *argv[])
{
    struct pin_input_arg input_arg;
    user_args_pin_parse(&input_arg, argc, argv);

    struct arg_parse_state *a_p_s = &(input_arg.parse_state);
    if (user_args_helper_state_is_exit_set(a_p_s))
    {
        exit(user_args_helper_state_get_code(a_p_s));
    }
}

int main(int argc, char *argv[])
{
    struct ameba *skel = NULL;
    int result = 0;

    parse_user_input(argc, argv);

    if (prog_op_create_lock_dir() != 0)
    {
        result = -1;
        goto exit;
    }

    skel = open_and_load_skel();
    if (!skel)
    {
        result = -1;
        goto rm_prog_op_lock_dir;
    }

    if (set_bpf_version_maps_with_current_versions(skel) != 0)
    {
        result = -1;
        goto skel_destroy;
    }

    if (set_default_control_input_map(skel) != 0)
    {
        result = -1;
        goto skel_destroy;
    }

    if (attach_progs(skel) != 0)
    {
        result = -1;
        goto skel_destroy;
    }

    if (pin_progs_and_maps(skel) != 0)
    {
        result = -1;
        goto skel_detach;
    }

    log_state_msg_with_current_pid(APP_STATE_OPERATIONAL_PID, "Pinned");

skel_detach:
    ameba__detach(skel);

skel_destroy:
    ameba__destroy(skel);

rm_prog_op_lock_dir:
    prog_op_remove_lock_dir();

exit:
    return result;
}
