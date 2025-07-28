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

#include <stdlib.h>

#include "user/prog/ameba/output.h"
#include "user/helper/log.h"
#include "user/jsonify/core.h"
#include "user/record/writer/dir.h"
#include "user/record/serializer/json.h"
#include "user/helper/prog_op.h"

//

static const struct record_serializer *log_serializer = &record_serializer_json;
static const struct record_writer *log_writer = &record_writer_dir;

//

static int alloc_and_get_data_as_json(void **dst, long *dst_len, void *ctx, void *data, size_t data_len)
{
    if (!dst || !dst_len)
        return -1;

    size_t buf_len = MAX_BUFFER_LEN;
    void *buf = malloc(sizeof(char) * buf_len);
    if (!buf)
        return -1;

    long data_copied_to_buf = log_serializer->serialize(buf, buf_len, data, data_len);
    if (data_copied_to_buf <= 0)
    {
        log_state_msg(APP_STATE_OPERATIONAL_WITH_ERROR, "Failed data conversion");
        free(buf);
        return -1;
    }

    *dst = buf;
    *dst_len = data_copied_to_buf;

    return 0;
}

int output_stdout_handle_ringbuf_data(void *ctx, void *data, size_t data_len)
{
    void *dst;
    long dst_len;
    int err = alloc_and_get_data_as_json(&dst, &dst_len, ctx, data, data_len);
    if (err != 0)
        goto exit;

    log_state_record(APP_STATE_OPERATIONAL, (char*)dst);

    free(dst);

exit:
    return err;
}

int output_log_handle_ringbuf_data(void *ctx, void *data, size_t data_len)
{
    void *dst;
    long dst_len;
    int err = alloc_and_get_data_as_json(&dst, &dst_len, ctx, data, data_len);
    if (err != 0)
        goto exit;

    int write_result = log_writer->write(dst, dst_len);
    if (write_result < 0)
    {
        log_state_msg(APP_STATE_OPERATIONAL_WITH_ERROR, "Failed data write");
        err = -1;
        goto free_dst;
    }

free_dst:
    free(dst);
exit:
    return err;
}

void output_close_log_writer()
{
    log_writer->close();
}

int output_setup_log_writer(struct arg_ameba *arg)
{
    if (!arg)
    {
        log_state_msg(
            APP_STATE_STOPPED_WITH_ERROR,
            "Failed output_setup_log_writer. NULL arguments"
        );
        return -1;
    }

    if (log_writer->set_init_args((void *)(arg), sizeof(struct arg_ameba)) != 0)
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