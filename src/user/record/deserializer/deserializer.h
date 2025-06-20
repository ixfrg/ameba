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

    A module to define the interface for record deserialization.

*/

#include <stddef.h>


/*
    A struct to define record deserialization. 
*/
struct record_deserializer {

    /*
        Deserialize the record.

        Call this function until it returns a positive value.

        The positive value indicates that record size that has been successfully deserialized.

        If an error occurs then the data is discarded. It is unforgiving i.e. it discards data
        if not enough space is available.

        The return value of 0 is used to handle the case where data is being processed but not
        ready yet.

        Return:
            +ive -> The size of the record that is deserialized and ready.
            -ive -> Error and any incomplete data is discarded.
            0    -> Not ready.

    */
    int (*deserialize)(void *data, size_t data_len);

    /*
        Read the deserialized record into the given 'dst'.

        Return:
            +ive -> Data written into dst
            -ive -> Error
            0    -> Undefined
    */
    int (*read)(void *dst, int dst_len);

    /*
        Return the space available in the internal buffer.
    */
    int (*get_available_space)(void);

};