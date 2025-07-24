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
#include "user/helpers/config.h"
#include "user/args/ameba.h"
#include "user/helpers/log.h"
#include "user/record/writer/dir.h"
#include "user/record/serializer/json.h"
#include "user/helpers/prog_op.h"
#include "user/jsonify/ameba.h"

//

static const struct record_serializer *log_serializer = &record_serializer_json;
static const struct record_writer *log_writer = &record_writer_dir;

static volatile int ameba_shutdown = 0;
static volatile ssize_t total_records_consumed = 0;

//

static int handle_ringbuf_data(void *ctx, void *data, size_t data_len)
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

    int write_result = log_writer->write(dst, data_copied_to_dst);
    if (write_result < 0)
    {
        log_state_msg(APP_STATE_OPERATIONAL_WITH_ERROR, "Failed data write");
        goto free_dst;
    }

free_dst:
    free(dst);
exit:
    return 0;
}

static struct ring_buffer * setup_output_ringbuf_reader()
{
    int ringbuf_fd = get_output_ringbuf_fd();
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

static void close_log_writer()
{
    log_writer->close();
}

static int setup_log_writer(struct ameba_input *ameba_input)
{
    if (!ameba_input)
        return -1;

    if (log_writer->set_init_args((void *)(ameba_input), sizeof(struct ameba_input)) != 0)
    {
        log_state_msg(
            APP_STATE_STOPPED_WITH_ERROR,
            "Failed to set init args for ameba log writer"
        );
        return -1;
    }

    if (log_writer->init() != 0)
    {
        log_state_msg(
            APP_STATE_STOPPED_WITH_ERROR,
            "Failed to create ameba log writer"
        );
        return -1;
    }
    return 0;
}

static void sig_handler(int sig)
{
    if (sig == SIGTERM || sig == SIGINT)
    {
        ameba_shutdown = 1;
        log_state_msg(APP_STATE_STOPPED_NORMALLY, "Stopping... received termination signal");
    }
}

static void parse_config_input(
    struct ameba_input *dst
)
{
    int argc = 0;
    char **argv = NULL;

    const char *config_path = AMEBA_CONFIG_FILE_PATH;

    if (parse_config_to_argv(config_path, &argc, &argv) != 0) {
        return;
    }

    struct ameba_input_arg config_arg;
    user_args_ameba_parse(&config_arg, NULL, argc, argv);

    for (int i = 0; i < argc; ++i) {
        free(argv[i]);
    }
    free(argv);

    struct arg_parse_state *a_p_s = &(config_arg.parse_state);
    if (user_args_helper_state_is_exit_set(a_p_s))
    {
        exit(user_args_helper_state_get_code(a_p_s));
    }
    *dst = config_arg.ameba_input;

    // jsonify_ameba_write_ameba_input_to_file(stdout, dst);
}

static void parse_user_input(
    struct ameba_input *dst,
    int argc, char *argv[]
)
{
    struct ameba_input initial_value;
    parse_config_input(&initial_value);

    struct ameba_input_arg input_arg;
    user_args_ameba_parse(&input_arg, &initial_value, argc, argv);

    struct arg_parse_state *a_p_s = &(input_arg.parse_state);
    if (user_args_helper_state_is_exit_set(a_p_s))
    {
        exit(user_args_helper_state_get_code(a_p_s));
    }

    *dst = input_arg.ameba_input;
}

int main(int argc, char *argv[])
{
    int result = 0;

    struct ameba_input ameba_input;

    parse_user_input(&ameba_input, argc, argv);

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

    if (setup_log_writer(&ameba_input) != 0)
    {
        result = -1;
        goto rm_prog_op_lock_dir;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct ring_buffer *ringbuf = setup_output_ringbuf_reader();
    if (!ringbuf)
    {
        result = -1;
        goto cleanup_log_writer;
    }

    // Rmove lock dir to allow future operations
    prog_op_remove_lock_dir();

    int timeout_ms = 10;
    while (ameba_shutdown == 0)
    {
        int records_consumed = ring_buffer__poll(ringbuf, timeout_ms);
        if (records_consumed >= 0)
            total_records_consumed += records_consumed;
        // Ignore errors TODO
    }
    
    ring_buffer__free(ringbuf);
    close_log_writer();

    log_state_msg(APP_STATE_STOPPED_NORMALLY, "Stopped");

    goto exit;

cleanup_log_writer:
    close_log_writer();

rm_prog_op_lock_dir:
    prog_op_remove_lock_dir();

exit:
    return result;
}
