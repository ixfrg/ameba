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
#include "user/config/read.h"
#include "user/args/read.h"
#include "user/helpers/log.h"
#include "user/helpers/prog_op.h"
#include "user/jsonify/ameba.h"
#include "user/progs/ameba/output.h"
#include "user/record/serializer/json.h"


static const struct record_serializer *log_serializer = &record_serializer_json;

static volatile int read_shutdown = 0;
static volatile ssize_t total_records_consumed = 0;


int output_stdout_handle_ringbuf_data(void *ctx, void *data, size_t data_len)
{
    size_t dst_len = MAX_BUFFER_LEN;
    void *dst = malloc(sizeof(char) * dst_len);
    if (!dst)
        goto exit;

    long data_copied_to_dst = log_serializer->serialize(dst, dst_len, data, data_len);
    if (data_copied_to_dst <= 0)
    {
        log_state_msg(APP_STATE_OPERATIONAL_WITH_ERROR, "Failed data conversion");
        goto free_dst;
    }

    log_state_msg(APP_STATE_OPERATIONAL, "%s\n", (char*)dst);

free_dst:
    free(dst);
exit:
    return 0;
}

static void sig_handler(int sig)
{
    if (sig == SIGTERM || sig == SIGINT)
    {
        read_shutdown = 1;
        log_state_msg(APP_STATE_STOPPED_NORMALLY, "Stopping... received termination signal");
    }
}

static void parse_user_input(
    struct read_input *dst,
    int argc, char *argv[]
)
{
    struct read_input initial_value;
    config_read_parse_default_config(&initial_value);

    struct read_input_arg input_arg;
    user_args_read_parse(&input_arg, &initial_value, argc, argv);

    struct arg_parse_state *a_p_s = &(input_arg.parse_state);
    if (user_args_helper_state_is_exit_set(a_p_s))
    {
        exit(user_args_helper_state_get_code(a_p_s));
    }

    *dst = input_arg.read_input;
}

int main(int argc, char *argv[])
{
    int result = 0;

    struct read_input ameba_input;
    parse_user_input(&ameba_input, argc, argv);

    if (prog_op_create_lock_dir() != 0)
    {
        result = -1;
        goto exit;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    result = prog_op_ameba_must_be_pinned();
    if (result != 0)
    {
        result = -1;
        goto rm_prog_op_lock_dir;
    }

    struct ring_buffer *ringbuf = prog_op_setup_output_ringbuf_reader(output_stdout_handle_ringbuf_data);
    if (!ringbuf)
    {
        result = -1;
        goto rm_prog_op_lock_dir;
    }

    log_state_msg_with_pid(APP_STATE_OPERATIONAL_PID, "Started", getpid());

    int timeout_ms = 100;
    while (read_shutdown == 0)
    {
        int records_consumed = ring_buffer__poll(ringbuf, timeout_ms);
        if (records_consumed >= 0)
            total_records_consumed += records_consumed;
        // Ignore errors TODO
    }
    
    ring_buffer__free(ringbuf);

    log_state_msg(APP_STATE_STOPPED_NORMALLY, "Stopped");

rm_prog_op_lock_dir:
    prog_op_remove_lock_dir();

exit:
    return result;
}
