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

#include <stddef.h>
#include <string.h>
#include "user/error.h"
#include "user/record/deserializer/deserializer.h"

/*
static const int max_buff_len = 1024;
static const unsigned char buf[max_buff_len];
static int current_buf_index = 0;
static int expected_data_size = 0;


static void reset_state()
{
    current_buf_index = 0;
    expected_data_size = 0;
    memset(&buf[0], 0, max_buff_len);
}
*/

// static int data_deserializer_binary_deserialize(void *data, size_t data_len)
// {
//     if (!data)
//     {
//         reset_state();
//         return ERR_DATA_INVALID;
//     }

//     if (data_len + current_buf_index > max_buff_len)
//     {
//         reset_state();
//         return ERR_DST_INSUFFICIENT;
//     }
    
//     if (current_buf_index == 0)
//     {
//         int size_t_len = sizeof(size_t);
//         if (data_len)
//         memcpy(&dst_c[i], &data_len, sizeof(size_t));
//     }
//     return 0;
// }

// static int data_deserializer_binary_read(void *dst, int dst_len)
// {
//     return 0;
// }


// const struct data_deserializer data_deserializer_binary = {
//     .deserialize = data_deserializer_binary_deserialize,
//     .read = data_deserializer_binary_read
// };
