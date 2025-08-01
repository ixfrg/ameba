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

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>


struct ring_buffer
{
    char *data;
    uint64_t size;
    uint64_t head;
    uint64_t tail;
};

/*
    Allocate a new ring buffer

    Returns:
        NULL  => If failed to alloc
        ptr to aloocated ring_buffer
*/
struct ring_buffer *ring_buffer_alloc(uint64_t size);

/*
    Free the allocated memory for ring_buffer
*/
void ring_buffer_free(struct ring_buffer *rb);

/*
    Discard all data.
*/
void ring_buffer_clear(struct ring_buffer *rb);

/*
    Returns:
        true   => It is full
        false  => It is not full
*/
bool ring_buffer_is_full(struct ring_buffer *rb);

/*
    Returns:
        true   => It is empty
        false  => It is not empty
*/
bool ring_buffer_is_empty(struct ring_buffer *rb);

/*
    Returns:
        The available space.
*/
uint64_t ring_buffer_available_capacity(struct ring_buffer *rb);

/*
    Add data.

    Returns:
        true   => If all the data is added
        false  => If not enough space available
*/
bool ring_buffer_push(struct ring_buffer *rb, char *data, uint64_t data_len);

/*
    Remove data.

    Returns:
        true   => If enough data available
        false  => If not enough data available
*/
bool ring_buffer_pop(struct ring_buffer *rb, char *data, uint64_t data_len);

/*
    Peek at data without removing it.

    Returns:
        true   => If enough data available
        false  => If not enough data available
*/
bool ring_buffer_peek(struct ring_buffer *rb, char *dst, uint64_t len);

/*
    Discard data without reading.

    Returns:
        true   => If enough data available
        false  => If not enough data available
*/
bool ring_buffer_discard(struct ring_buffer *rb, uint64_t len);