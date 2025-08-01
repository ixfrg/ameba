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



auditctl_bin="/usr/sbin/auditctl"
user_to_audit=1001
syscalls_to_audit=all


cmd=


function print_status() {
    echo ""
    echo "${auditctl_bin}" -s
    "${auditctl_bin}" -s
    echo ""
    echo "${auditctl_bin}" -l
    "${auditctl_bin}" -l
    echo ""
}


function clear_rules() {
    "${auditctl_bin}" -D
}


function set_rules() {
    "${auditctl_bin}" -a exit,always -F arch=b64 -S ${syscalls_to_audit} -F uid=${user_to_audit}
}


function set_default_buffer() {
    "${auditctl_bin}" -b 1000000
}


function print_help() {
    echo "Usage:"
    echo ""
    echo "${0} CMD"
    echo ""
    echo "CMD:"
    echo "  set:    Set default audit rules"
    echo "  clear:  Clear all audit rules"
    echo "  status: Show status"
    echo "  help:   Show help"
    echo ""
}


function parse_and_set_global_args() {
    cmd="${1}"
}


function execute_cmd() {
    case $cmd in
        "set")
            set_rules
            set_default_buffer
            ;;
        "clear")
            clear_rules
            ;;
        "status")
            print_status
            ;;
        "help")
            print_help
            exit 0
            ;;
        "")
            echo "No cmd specified by the user. See help."
            exit 1
            ;;
        *)
            echo "Unknown cmd: '${cmd}'"
            print_help
            exit 1
            ;;
    esac
}


function main() {
    parse_and_set_global_args $@
    execute_cmd
}


main $@