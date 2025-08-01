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

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "user/helper/ring_buffer.h"


struct ring_buffer *ring_buffer_alloc(uint64_t size)
{
    struct ring_buffer *rb = malloc(sizeof(struct ring_buffer));
    if (!rb)
        return NULL;

    if (size == UINT64_MAX)
    {
        return NULL;
    }

    // Reserve 1 for full check
    size += 1;

    rb->data = malloc(sizeof(char) * size);
    if (!rb->data)
    {
        free(rb);
        return NULL;
    }

    rb->size = size;
    rb->head = 0;
    rb->tail = 0;

    return rb;
}

void ring_buffer_free(struct ring_buffer *rb)
{
    if (!rb)
        return;
    if (rb->data)
        free(rb->data);
    free(rb);
}

void ring_buffer_clear(struct ring_buffer *rb)
{
    if (!rb)
        return;
    rb->head = 0;
    rb->tail = 0;
}

bool ring_buffer_is_full(struct ring_buffer *rb)
{
    return ((rb->head + 1) % rb->size) == rb->tail;
}

bool ring_buffer_is_empty(struct ring_buffer *rb)
{
    return rb->head == rb->tail;
}

uint64_t ring_buffer_available_capacity(struct ring_buffer *rb)
{
    if (rb->head >= rb->tail)
        return rb->size - (rb->head - rb->tail) - 1;
    else
        return rb->tail - rb->head - 1;
}

bool ring_buffer_push(struct ring_buffer *rb, char *data, uint64_t data_len)
{
    if (ring_buffer_available_capacity(rb) < data_len)
        return false;

    for (uint64_t i = 0; i < data_len; ++i)
    {
        rb->data[rb->head] = data[i];
        rb->head = (rb->head + 1) % rb->size;
    }

    return true;
}

bool ring_buffer_pop(struct ring_buffer *rb, char *data, uint64_t data_len)
{
    if (((rb->head + rb->size - rb->tail) % rb->size) < data_len)
        return false;

    for (uint64_t i = 0; i < data_len; ++i)
    {
        data[i] = rb->data[rb->tail];
        rb->tail = (rb->tail + 1) % rb->size;
    }

    return true;
}

bool ring_buffer_peek(struct ring_buffer *rb, char *dst, uint64_t len)
{
    if (ring_buffer_available_capacity(rb) < len)
        return false;

    uint64_t temp_tail = rb->tail;

    for (uint64_t i = 0; i < len; ++i)
    {
        dst[i] = rb->data[temp_tail];
        temp_tail = (temp_tail + 1) % rb->size;
    }

    return true;
}

bool ring_buffer_discard(struct ring_buffer *rb, uint64_t len)
{
    if (ring_buffer_available_capacity(rb) < len)
        return false;

    rb->tail = (rb->tail + len) % rb->size;
    return true;
}