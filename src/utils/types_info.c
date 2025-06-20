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

#include <stdio.h>
#include <sys/types.h>
#include "common/types.h"


int main(int argc, char *argv[])
{
    printf("RECORD_SIZE_AUDIT_LOG_EXIT=%d\n", RECORD_SIZE_AUDIT_LOG_EXIT);
    printf("RECORD_SIZE_NEW_PROCESS=%d\n", RECORD_SIZE_NEW_PROCESS);
    printf("RECORD_SIZE_CRED=%d\n", RECORD_SIZE_CRED);
    printf("RECORD_SIZE_NAMESPACE=%d\n", RECORD_SIZE_NAMESPACE);
    printf("RECORD_SIZE_CONNECT=%d\n", RECORD_SIZE_CONNECT);
    printf("RECORD_SIZE_ACCEPT=%d\n", RECORD_SIZE_ACCEPT);
    printf("RECORD_SIZE_SEND_RECV=%d\n", RECORD_SIZE_SEND_RECV);
    printf("RECORD_SIZE_BIND=%d\n", RECORD_SIZE_BIND);
    printf("RECORD_SIZE_KILL=%d\n", RECORD_SIZE_KILL);
    return 0;
}