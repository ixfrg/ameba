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
#include <stdlib.h>

#include "common/types.h"
#include "common/version.h"
#include "user/helper/log.h"
#include "user/helper/prog_op.h"
#include "user/arg/control.h"
#include "user/jsonify/control.h"


static void log_control_prev_and_current(struct control *prev, struct control *curr)
{
    if (!prev && !curr)
        return;

    int combined_dst_len = 1024;
    char combined_dst[combined_dst_len];
    struct json_buffer combined_js;
    jsonify_core_init(&combined_js, combined_dst, combined_dst_len);
    jsonify_core_open_obj(&combined_js);

    if (prev)
    {
        int prev_dst_len = 512;
        char prev_dst[prev_dst_len];
        struct json_buffer prev_js;
        jsonify_core_init(&prev_js, prev_dst, prev_dst_len);
        jsonify_core_open_obj(&prev_js);
        jsonify_control_write_control(&prev_js, prev);
        jsonify_core_close_obj(&prev_js);

        jsonify_core_write_json(&combined_js, "previous", &prev_js);
    }

    if (curr)
    {
        int curr_dst_len = 512;
        char curr_dst[curr_dst_len];
        struct json_buffer curr_js;
        jsonify_core_init(&curr_js, curr_dst, curr_dst_len);
        jsonify_core_open_obj(&curr_js);
        jsonify_control_write_control(&curr_js, curr);
        jsonify_core_close_obj(&curr_js);

        jsonify_core_write_json(&combined_js, "current", &curr_js);
    }

    jsonify_core_close_obj(&combined_js);

    log_state_msg_and_child_js(APP_STATE_OPERATIONAL, "Pinned", "control", &combined_js);
}

int main(int argc, char *argv[])
{
    int result = 0;

    struct arg_control arg_current_control;
    struct arg_control_with_parse_state arg_control_next_with_state;

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

    if (prog_op_get_control_in_map(&arg_current_control.control) != 0)
    {
        return -1;
    }

    arg_control_parse(&arg_control_next_with_state, &arg_current_control, argc, argv);
    struct arg_parse_state *a_p_s = &(arg_control_next_with_state.parse_state);
    if (arg_parse_state_is_exit_set(a_p_s))
    {
        result = arg_parse_state_get_code(a_p_s);
        goto rm_prog_op_lock_dir;
    }

    if (argc == 1)
    {
        // no user argument. Log the current and exit.
        log_control_prev_and_current(NULL, &arg_current_control.control);
        goto rm_prog_op_lock_dir;
    }

    if (prog_op_set_control_in_map(&arg_control_next_with_state.arg.control) != 0)
    {
        result = -1;
        goto rm_prog_op_lock_dir;
    }

    log_control_prev_and_current(&arg_current_control.control, &arg_control_next_with_state.arg.control);

rm_prog_op_lock_dir:
    prog_op_remove_lock_dir();

exit:
    return result;
}
