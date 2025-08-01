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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>

#include "user/include/error.h"

#include "user/jsonify/core.h"


/*
    Write the data with the specified format into the json_buffer.

    Return:
        0    => Error i.e. failed to write data to json_buffer.
        +ive => The number of bytes written.
*/
static int jsonify_core_snprintf(struct json_buffer *s, const char *format, ...)
{
    va_list args;
    int charsWritten;

    if (s->overflown) return 0;

    va_start(args, format);

    charsWritten = vsnprintf(&(s->buf[s->bufIdx]), s->remBufLen, format, args);
    if (charsWritten >= s->remBufLen)
    {
        // i.e. the vsnprintf function truncated the result.
        s->overflown = 1;
        s->remBufLen = 0;
        va_end(args);
        return 0; // The json buffer is not usable anymore.
    }
    else
    {
        s->remBufLen -= charsWritten;
        s->bufIdx += charsWritten;
        va_end(args);
        return charsWritten;
    }
}

/*
    A helper function to write the key-val pair separater ','.

    This function can be used to write ',' everytime any other jsonify_* function
    is used write any key-val.

    Return:
        See 'jsonify_core_snprintf'.
*/
static int jsonify_core_write_element_divider(struct json_buffer *s)
{
    if (s->bufIdx > 1)
        return jsonify_core_snprintf(s, ",");
    return 0;
}

/*
    Get reference to internal buffer used by json_buffer and it's size.

    Return:
        0    => Success
        -ive => Error
*/
int jsonify_core_get_internal_buf_ptr(
    struct json_buffer *s,
    char **buf_ptr, int *buf_size
)
{
    *buf_ptr = &(s->buf[0]);
    *buf_size = s->bufIdx;
    return 0;
}

int jsonify_core_get_total_chars_written(struct json_buffer *s)
{
    return s->bufIdx;
}

int jsonify_core_write_newline(struct json_buffer *s)
{
    return jsonify_core_snprintf(s, "\n");
}

int jsonify_core_has_overflown(struct json_buffer *s)
{
    return s->overflown;
}

int jsonify_core_init(struct json_buffer *s, char *dst_buf, unsigned int dst_buf_len)
{
    s->buf = dst_buf;
    s->maxBufLen = dst_buf_len - 1;
    s->bufIdx = 0;
    s->remBufLen = s->maxBufLen - s->bufIdx;
    s->overflown = 0;
    memset(&(s->buf[0]), 0, s->maxBufLen);
    return 0;
}

int jsonify_core_open_obj(struct json_buffer *s)
{
    return jsonify_core_snprintf(s, "{");
}

int jsonify_core_close_obj(struct json_buffer *s)
{
    return jsonify_core_snprintf(s, "}");
}

int jsonify_core_write_bytes(struct json_buffer *s, const char *key, unsigned char *val, int val_size)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":\"", key);
    for (size_t i = 0; i < val_size; i++)
    {
        total += jsonify_core_snprintf(s, "%02x", val[i]);
    }
    total += jsonify_core_snprintf(s, "\"");
    return total;
}

int jsonify_core_write_int(struct json_buffer *s, const char *key, int val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%d", key, val);
    return total;
}

int jsonify_core_write_uint(struct json_buffer *s, const char *key, unsigned int val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%u", key, val);
    return total;
}

int jsonify_core_write_str(struct json_buffer *s, const char *key, const char *val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":\"%s\"", key, val);
    return total;
}

int jsonify_core_write_as_literal(struct json_buffer *s, const char *key, const char *val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%s", key, val);
    return total;
}

int jsonify_core_write_json(struct json_buffer *s, const char *key, struct json_buffer *js_child)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);

    char *js_child_buf_ptr;
    int js_child_buf_ptr_size;
    if (jsonify_core_get_internal_buf_ptr(js_child, &js_child_buf_ptr, &js_child_buf_ptr_size) == 0)
    {
        total += jsonify_core_snprintf(s, "\"%s\":%s", key, js_child_buf_ptr);
    }
    return total;
}

int jsonify_core_write_ulong(struct json_buffer *s, const char *key, unsigned long val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%lu", key, val);
    return total;
}

int jsonify_core_write_ulonglong(struct json_buffer *s, const char *key, unsigned long long val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%llu", key, val);
    return total;
}

int jsonify_core_write_long(struct json_buffer *s, const char *key, long val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%ld", key, val);
    return total;
}

int jsonify_core_write_short(struct json_buffer *s, const char *key, short int val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%hd", key, val);
    return total;
}

int jsonify_core_write_timespec64(struct json_buffer *s, const char *key, long long tv_sec, long tv_nsec)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%llu.%03lu", key, (unsigned long long)tv_sec, tv_nsec/1000000);
    return total;
}