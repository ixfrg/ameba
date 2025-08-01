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

    A module to handle api server through unix socket

*/


/*
    Start handling requests sent to api server socket.

    Returns:
        -1   => Error
        0    => Returns after 'api_server_socket_stop'
*/
int api_server_socket_start(char *unix_socket_path);

/*
    Stop handling requests.

    Returns:
        -1   => Error
        0    => Normal return
*/
int api_server_socket_stop();

/*
    Returns:
        0   => No
        1   => Yes
*/
int api_server_socket_is_running();