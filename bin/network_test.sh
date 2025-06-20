#!/bin/bash

# SPDX-License-Identifier: GPL-3.0-or-later
# AMEBA - A Minimal eBPF-based Audit: an eBPF-based Linux telemetry collection tool.
# Copyright (C) 2025  Hassaan Irshad
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


ip_address=localhost
server_port=5689

temp_dir=
server_output_file=
client_input_file=

server_pid=
client_pid=


function print_status() {
    local client_input_contents=
    local server_output_contents=
    if test -f "${client_input_file}"; then
        client_input_contents="$(cat "${client_input_file}")"
    fi
    if test -f "${server_output_file}"; then
        server_output_contents="$(cat "${server_output_file}")"
    fi
cat <<-EOF
{
"ip_address":"${ip_address}"
,"server_port":${server_port}
,"server_output_file":"${server_output_file}"
,"client_input_file":"${client_input_file}"
,"server_pid":"${server_pid}"
,"client_pid":"${client_pid}"
,"client_input_contents":"${client_input_contents}"
,"server_output_contents":"${server_output_contents}"
}
EOF
}


function init_temp_dir_and_files() {
    temp_dir=$(mktemp -d)
    server_output_file="${temp_dir}/server_output"
    client_input_file="${temp_dir}/client_input"
}


function create_client_input_file() {
    echo "a" > "${client_input_file}"
    # echo "b" >> "${client_input_file}"
}


function cleanup_temp_dir_and_files() {
    rm -r "${temp_dir}"
}


function stop_server() {
    kill -9 "${server_pid}"
}


function start_server() {
    nc -4 -l "${ip_address}" ${server_port} 2>&1 &> "${server_output_file}" &
    server_pid=$!
}


function pause_after_server_start() {
    sleep 3
}


function pause_after_client_run() {
    sleep 3
}


function stop_client() {
    kill -9 "${client_pid}"
}


function start_client() {
    nc -4 "${ip_address}" ${server_port} < "${client_input_file}" &
    client_pid=$!
}


function main() {
    # ps aux | grep " nc "

    init_temp_dir_and_files
    create_client_input_file

    start_server
    pause_after_server_start

    # print_status

    start_client
    
    pause_after_client_run

    print_status

    stop_client
    stop_server

    cleanup_temp_dir_and_files
}


main