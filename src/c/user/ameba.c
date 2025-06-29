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

#include "common/types.h"

#include "user/args/control.h"
#include "user/args/user.h"
#include "user/jsonify/control.h"
#include "user/jsonify/user.h"
#include "common/constants.h"
#include "user/error.h"

#include "user/record/serializer/serializer.h"
#include "user/record/writer/writer.h"

#include "user/helpers/log.h"

#include "ameba.skel.h"

//

extern const struct record_serializer record_serializer_json;
extern const struct record_writer record_writer_file;
extern const struct record_writer record_writer_net;

//

static const struct record_serializer *default_record_serializer;
static const struct record_writer *default_record_writer;

//

static struct ameba *skel = NULL;

//

static int select_default_output_writer(
    struct user_input *input,
    void **o_writer_args_ptr,
    size_t *o_writer_args_ptr_size
)
{
    switch (input->o_type)
    {
        case OUTPUT_FILE:
            *o_writer_args_ptr = &(input->output_file);
            *o_writer_args_ptr_size = sizeof(input->output_file);
            default_record_writer = &record_writer_file;
            return 0;
        case OUTPUT_NET:
            *o_writer_args_ptr = &(input->output_net);
            *o_writer_args_ptr_size = sizeof(input->output_net);
            default_record_writer = &record_writer_net;
            return 0;
        default:
            return 1;
    }
}


static int select_default_record_serializer()
{
    default_record_serializer = &record_serializer_json;
    return 0;
}

/*
    Helper function to use the json logger to log a string.
*/
static void _log_state_msg(app_state_t st, const char *s)
{
    int buf_size = 512;
    char buf[buf_size];

    struct json_buffer js_msg;
    jsonify_core_init(&js_msg, &buf[0], buf_size);
    jsonify_core_open_obj(&js_msg);
    jsonify_core_write_str(&js_msg, "msg", s);
    jsonify_core_close_obj(&js_msg);

    log_state(st, &js_msg);
}

/*
    Helper function to use the json logger to log a json_obj.
*/
static void _log_state_msg_and_js(
    app_state_t st, 
    const char *msg_val,
    const char *js_key, struct json_buffer *js_val
)
{
    char *js_val_buf_ptr;
    int js_val_buf_size;

    int buf_size = 512;
    char buf[buf_size];

    struct json_buffer js_msg;
    jsonify_core_init(&js_msg, &buf[0], buf_size);
    jsonify_core_open_obj(&js_msg);
    jsonify_core_write_str(&js_msg, "msg", msg_val);
    if (jsonify_core_get_internal_buf_ptr(js_val, &js_val_buf_ptr, &js_val_buf_size) == 0)
    {
        jsonify_core_write_as_literal(&js_msg, js_key, js_val_buf_ptr);
    }
    jsonify_core_close_obj(&js_msg);

    log_state(st, &js_msg);
}

static void _log_state_msg_with_pid(
    app_state_t st,
    const char *msg_val,
    pid_t pid
)
{
    int buf_size = 128;
    char buf[buf_size];

    struct json_buffer js_msg;
    jsonify_core_init(&js_msg, &buf[0], buf_size);
    jsonify_core_open_obj(&js_msg);
    jsonify_core_write_str(&js_msg, "msg", msg_val);
    jsonify_core_write_int(&js_msg, "pid", pid);
    jsonify_core_close_obj(&js_msg);

    log_state(st, &js_msg);
}

static int init_output_writer(struct user_input *input){
    void *record_writer_init_args = NULL;
    size_t record_writer_init_args_size = 0;
    
    int err = select_default_output_writer(input, &record_writer_init_args, &record_writer_init_args_size);
    if (err)
    {
        _log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Error selecting a valid output writer");
        return -1;
    }

    err = select_default_record_serializer();
    if (err)
    {
        _log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Error selecting a valid record serializer");
        return -1;
    }

    err = default_record_writer->set_init_args(
        record_writer_init_args, record_writer_init_args_size
    );
    if (err != 0)
    {
        _log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Error setting init args for the output writer");
        return -1;
    }

    err = default_record_writer->init();
    if (err != 0)
    {
        _log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Error initing output writer");
        return -1;
    }
    return 0;
}

static void close_output_writer()
{
    default_record_writer->close();
}

static int handle_ringbuf_data(void *ctx, void *data, size_t data_len)
{
    size_t dst_len = MAX_BUFFER_LEN;
    void *dst = malloc(sizeof(char) * dst_len);
    if (!dst)
        goto exit;

    long data_copied_to_dst = default_record_serializer->serialize(dst, dst_len, data, data_len);
    if (data_copied_to_dst <= 0)
    {
        _log_state_msg(APP_STATE_OPERATIONAL_WITH_ERROR, "Failed data conversion");
        goto free_dst;
    }

    int write_result = default_record_writer->write(dst, data_copied_to_dst);
    if (write_result < 0)
    {
        _log_state_msg(APP_STATE_OPERATIONAL_WITH_ERROR, "Failed data write");
        goto free_dst;
    }

free_dst:
    free(dst);
exit:
    return 0;
}

static void sig_handler(int sig)
{
    if (sig == SIGTERM)
    {
        close_output_writer();
        if (skel != NULL)
        {
            ameba__destroy(skel);
        }
        _log_state_msg(APP_STATE_STOPPED_NORMALLY, "Stopped... received termination signal");
        exit(0);
    }
}

static int parse_user_input(struct user_input *input, int argc, char *argv[])
{
    int ret = user_args_user_must_parse_user_input(argc, argv);
    if(ret == 0){
        memcpy(input, &global_user_input, sizeof(*input));
    }
    return ret;
}

static int update_control_input_map(struct control_input *input)
{
    int update_flags;

    update_flags = BPF_ANY;
    // update_flags |= BPF_F_LOCK;

    int key = 0;
    int ret = bpf_map__update_elem(
        skel->maps.control_input_map, 
        &key, sizeof(key),
        input, sizeof(struct control_input),
        update_flags
    );

    return ret;
}

static int get_control_input_from_map(struct control_input *result)
{
    int lookup_flags;
    lookup_flags = BPF_ANY;
    // lookup_flags |= BPF_F_LOCK;

    int key = 0;
    int ret = bpf_map__lookup_elem(
        skel->maps.control_input_map, 
        &key, sizeof(key),
        result, sizeof(struct control_input),
        lookup_flags
    );
    return ret;
}

static void print_current_control_input()
{
    struct control_input result;
    int dst_len = 512;
    char dst[dst_len];

    if (get_control_input_from_map(&result) != 0)
    {
        _log_state_msg(APP_STATE_STARTING, "Failed to get control input entry from BPF map");
        return;
    }

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    jsonify_control_write_control_input(&s, &result);

    jsonify_core_close_obj(&s);

    _log_state_msg_and_js(
        APP_STATE_STARTING, 
        "Control input in BPF map",
        "control_input", &s
    );
}

static void print_user_input(struct user_input *user_input)
{
    int dst_len = 1024;
    char dst[dst_len];

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    jsonify_user_write_user_input(&s, user_input);

    jsonify_core_close_obj(&s);

    _log_state_msg_and_js(
        APP_STATE_STARTING, 
        "User arguments",
        "user_input", &s
    );
}

int main(int argc, char *argv[])
{
    int result;
    struct ring_buffer *ringbuf = NULL;
    int err, ringbuf_map_fd;
    struct user_input input;
    
    result = parse_user_input(&input, argc, argv);

    if (result != 0)
    {
        return result;
    }

    print_user_input(&input);

    signal(SIGTERM, sig_handler);
    _log_state_msg(APP_STATE_STARTING, "Registered signal handler");

    skel = ameba__open_and_load();
    if (!skel)
    {
        _log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to load bpf skeleton");
        result = 1;
        return result;
    }

    result = update_control_input_map(&input.c_in);
    if (result != 0)
    {
        _log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Error updating control input");
        result = 1;
        goto skel_destroy;
    }

    print_current_control_input();

    err = ameba__attach(skel);
    if (err != 0)
    {
        _log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Error attaching skeleton");
        result = 1;
        goto skel_destroy;
    }

    // Locate ring buffer
    ringbuf_map_fd = bpf_object__find_map_fd_by_name(skel->obj, OUTPUT_RINGBUF_MAP_NAME);
    if (ringbuf_map_fd < 0)
    {
        _log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to find ring buffer map object");
        result = 1;
        goto skel_detach;
    }

    ringbuf = ring_buffer__new(ringbuf_map_fd, handle_ringbuf_data, NULL, NULL);

    int writer_error = init_output_writer(&input);
    if (writer_error != 0)
    {
        _log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Error creating output writer");
        result = 1;
        goto skel_detach;
    }

     _log_state_msg_with_pid(APP_STATE_OPERATIONAL_PID, "Started successfully", getpid());

    while (ring_buffer__poll(ringbuf, -1) >= 0)
    {
        // collect prov in callback
    }

// log_file_close:
    close_output_writer();

skel_detach:
    ameba__detach(skel);

skel_destroy:
    ameba__destroy(skel);

// exit:
    return result;
}
