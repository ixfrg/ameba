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

    A module to define the interface for record writer.

*/

#include <stddef.h>
#include "common/types.h"


struct record_writer
{
    /*
        Function to set arguments to used in 'init' function.

        Return:
            -ive => Invalid argument 
            0    => Success
    */
    int (*set_init_args) (void *ptr, size_t ptr_len);
    /*
        Function to initialize the writer.

        Return:
            -ive => Failure
            0    => Success
    */
    int (*init) ();
    /*
        Function to close the writer.

        Return:
            Not handled.
    */
    int (*close) ();
    /*
        Write the given record to the writer.

        Return:
            -2  => The writer is not initialized
            -1  => The underlying write failed
            >=0 => The bytes written
    */
    int (*write) (void *data, size_t data_len);
};
