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

#pragma once

/*

    A module to help with JSON object building.
    
    It defines the core components:
    
    1. json_buffer.
    2. Functions to write basic types to json_buffer.

*/


/*
    The maximum buffer length allowed for json_buffer.

    Dependent on the context and the system.

    The default value is completely arbitrary.
*/
#define MAX_BUFFER_LEN 1024


/*
    A struct to hold state required for building a JSON object.

    NOTE: Only capable of building a JSON object.

    API usage:
        1. jsonify_core_init
        2. jsonify_core_open_obj
        3. Write data into json_buffer using the various available functions
        4. jsonify_core_close_obj
        5. Use 'jsonify_core_has_overflown' to check if data is truncated
        6. Get data from json_buffer.buf

*/
struct json_buffer
{
    char *buf;
    int bufIdx;
    int maxBufLen;
    int remBufLen;
    int overflown;
};


/*
    Return the number of chars written to the json_buffer so far.
*/
int jsonify_core_get_total_chars_written(struct json_buffer *s);

/*
    A helper function to write newline.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_core_write_newline(struct json_buffer *s);

/*
    Check if the json_buffer has overflown.

    Return:
        0 => No.
        1 => Yes.
*/
int jsonify_core_has_overflown(struct json_buffer *s);

/*
    Initialize the given json_buffer.

    Responsibility of the user to pass valid values.

    Return:
        0 => Success.
        No failure.
*/
int jsonify_core_init(struct json_buffer *s, char *dst_buf, unsigned int dst_buf_len);

/*
    Write '{'.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_core_open_obj(struct json_buffer *s);

/*
    Write '}'.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_core_close_obj(struct json_buffer *s);

/*
    Write [,]"key":"val".
    
    'val' as bytes (in hex) where the number of bytes are given by 'val_size'.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_core_write_bytes(struct json_buffer *s, const char *key, unsigned char *val, int val_size);

/*
    Write [,]"key"=val where val is a signed integer.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_core_write_int(struct json_buffer *s, const char *key, int val);

/*
    Write [,]"key"=val where val is an unsigned integer.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_core_write_uint(struct json_buffer *s, const char *key, unsigned int val);

/*
    Write [,]"key"="val" where val is a null-terminated string.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_core_write_str(struct json_buffer *s, const char *key, const char *val);

/*
    Write [,]"key"=val where val is a null-terminated literal.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_core_write_as_literal(struct json_buffer *s, const char *key, const char *val);

/*
    Write [,]"key"=val where val is an unsigned long.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_core_write_ulong(struct json_buffer *s, const char *key, unsigned long val);

/*
    Write [,]"key"=val where val is an unsigned long long.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_core_write_ulonglong(struct json_buffer *s, const char *key, unsigned long long val);

/*
    Write [,]"key"=val where val is a signed long.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_core_write_long(struct json_buffer *s, const char *key, long val);

/*
    Write [,]"key"=val where val is a short signed integer.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_core_write_short(struct json_buffer *s, const char *key, short int val);

/*
    Write [,]"key"=tv_sec.msec where 'tv_sec' is the number of seconds, and msec=tv_nsec/1000000, and
    tv_nsec is the number of nanoseconds.
    
    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_core_write_timespec64(struct json_buffer *s, const char *key, long long tv_sec, long tv_nsec);
