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

#include "user/progs/ameba/output.h"
#include "user/helpers/log.h"
#include "user/jsonify/core.h"
#include "user/record/writer/dir.h"
#include "user/record/serializer/json.h"
#include "user/helpers/prog_op.h"

//

static const struct record_serializer *log_serializer = &record_serializer_json;
static const struct record_writer *log_writer = &record_writer_dir;

//

int output_handle_ringbuf_data(void *ctx, void *data, size_t data_len)
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

void output_close_log_writer()
{
    log_writer->close();
}

int output_setup_log_writer(struct ameba_input *ameba_input)
{
    if (!ameba_input)
    {
        log_state_msg(
            APP_STATE_STOPPED_WITH_ERROR,
            "Failed output_setup_log_writer. NULL arguments"
        );
        return -1;
    }

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