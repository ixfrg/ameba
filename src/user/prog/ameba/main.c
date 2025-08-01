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

#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <bpf/bpf.h>
#include <pthread.h>
#include <netinet/in.h>
#include <syslog.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <bpf/libbpf.h>

#include "common/constants.h"
#include "user/config/ameba.h"
#include "user/config/control.h"
#include "user/config/pin.h"
#include "user/config/unpin.h"
#include "user/arg/ameba.h"
#include "user/arg/pin.h"
#include "user/arg/control.h"
#include "user/helper/log.h"
#include "user/helper/prog_op.h"
#include "user/jsonify/ameba.h"
#include "user/prog/ameba/output.h"


static volatile int ameba_shutdown = 0;
static volatile ssize_t total_records_consumed = 0;


static void sig_handler(int sig)
{
    if (sig == SIGTERM || sig == SIGINT)
    {
        ameba_shutdown = 1;
        log_state_msg(APP_STATE_STOPPED_NORMALLY, "Stopping... received termination signal");
    }
}

static void parse_user_input(
    struct arg_ameba *dst,
    int argc, char *argv[]
)
{
    struct arg_ameba initial_value;
    config_ameba_parse_default_config(&initial_value);

    struct arg_ameba_with_parse_state input_arg;
    arg_ameba_parse(&input_arg, &initial_value, argc, argv);

    struct arg_parse_state *a_p_s = &(input_arg.parse_state);
    if (arg_parse_state_is_exit_set(a_p_s))
    {
        exit(arg_parse_state_get_code(a_p_s));
    }

    *dst = input_arg.arg;
}

int run(
    struct arg_ameba *arg_ameba,
    struct arg_pin *arg_pin,
    struct arg_unpin *arg_unpin,
    struct arg_control *arg_control
)
{
    if (!arg_ameba || !arg_pin || !arg_unpin || !arg_control)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed run. Null argument(s)");
        return -1;
    }

    int result = 0;

    if (prog_op_create_lock_dir() != 0)
    {
        result = -1;
        goto exit;
    }

    if (output_setup_log_writer(arg_ameba) != 0)
    {
        result = -1;
        goto rm_prog_op_lock_dir;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    result = prog_op_pin_bpf_progs_and_maps(arg_pin, &arg_control->control);
    if (result != 0)
    {
        result = -1;
        goto cleanup_log_writer;
    }

    int (*handle_ringbuf_data)(void *ctx, void *data, size_t data_len);
    if (arg_ameba->output_stdout == 1)
        handle_ringbuf_data = output_stdout_handle_ringbuf_data;
    else
        handle_ringbuf_data = output_log_handle_ringbuf_data;
    struct ring_buffer *ringbuf = prog_op_setup_output_ringbuf_reader(handle_ringbuf_data);
    if (!ringbuf)
    {
        result = -1;
        goto unpin_bpf;
    }

    // Remove lock dir to allow future operations
    prog_op_remove_lock_dir();

    log_state_msg_with_pid(APP_STATE_OPERATIONAL_PID, "Started", getpid());

    int timeout_ms = 100;
    while (ameba_shutdown == 0)
    {
        int records_consumed = ring_buffer__poll(ringbuf, timeout_ms);
        if (records_consumed >= 0)
            total_records_consumed += records_consumed;
        // Ignore errors TODO
    }
    
    ring_buffer__free(ringbuf);
    output_close_log_writer();
    prog_op_unpin_bpf_progs_and_maps(arg_unpin);

    log_state_msg(APP_STATE_STOPPED_NORMALLY, "Stopped");

    goto exit;

unpin_bpf:
    prog_op_unpin_bpf_progs_and_maps(arg_unpin);

cleanup_log_writer:
    output_close_log_writer();

rm_prog_op_lock_dir:
    prog_op_remove_lock_dir();

exit:
    return result;
}

int main(int argc, char *argv[])
{
    struct arg_ameba arg_ameba;
    parse_user_input(&arg_ameba, argc, argv);

    struct arg_pin arg_pin;
    config_pin_parse_default_config(&arg_pin);

    struct arg_unpin arg_unpin;
    config_unpin_parse_default_config(&arg_unpin);

    struct arg_control arg_control;
    config_control_parse_default_config(&arg_control);

    return run(
        &arg_ameba,
        &arg_pin,
        &arg_unpin,
        &arg_control
    );
}
