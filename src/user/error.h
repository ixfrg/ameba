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

#define ERR_DST_INVALID -1
#define ERR_DST_INSUFFICIENT -2
#define ERR_RECORD_INVALID -3
#define ERR_RECORD_INVALID_HEADER -4
#define ERR_RECORD_INVALID_MAGIC -5
#define ERR_RECORD_SIZE_MISMATCH -6
#define ERR_RECORD_UNKNOWN -7