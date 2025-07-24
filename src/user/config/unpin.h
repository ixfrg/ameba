// SPDX-License-Identifier: GPL-3.0-or-later
/*
unpin - A Minimal eBPF-based Audit: an eBPF-based Linux telemetry collection tool.
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

#include "user/args/unpin.h"
#include "user/config/config.h"

/*
    Function to populate 'dst' from config file at path 'file_path'

    Returns:
        Does not return on failure!
        On success, 'dst' is populated
*/
void config_unpin_parse_config(char *file_path, struct unpin_input *dst);

/*
    Function to populate 'dst' from default config file at path '${install_prefx}/etc/ameba/unpin.conf'

    Returns:
        Does not return on failure!
        On success, 'dst' is populated
*/
void config_unpin_parse_default_config(struct unpin_input *dst);