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
    Function to read a config file of the format:

    ```
    word1 word2 word3
    # i am a comment
    word4 word5
    word6 
    ```

    to malloc argv_out as

    ["<file's base name>", "word1", "word2", "word3", "word4", "word5", "word6"]

    and argc_out as 7.

    Note: Ignore the first value '<file's base name>'... it is used for compatibility with argp configuration.

    Note: argv_out is malloc'ed and should be freed by the user.

    Return:
        0   => Success
        -1  => Error
*/

int config_parse_as_argv(const char *filename, int *argc_out, char ***argv_out);